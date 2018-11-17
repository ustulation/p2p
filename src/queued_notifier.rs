use mio::{Poll, Token};
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use {Interface, NatError, NatMsg, NatState};

type Func<UserData> = Box<FnMut(&mut Interface, &Poll, UserData) + 'static>;

/// Fire Queued Requests.
///
/// Since there's always a high chance of multiple borrows of `RefCell` which can lead to runtime
/// panics specially during callback invocation, it's a lot safer to post a queued response
/// instead. This allows all the borrows to end before the next borrow as the control is first
/// returned back to the event loop.
///
/// Panics can happen while borrowing an already active borrow of the parent or the child - i.e.,
/// in either direction. Consider the following (will panic as explained inline):
///
/// # Examples
///
/// ```should_panic
/// # use std::rc::{Rc, Weak};
/// # use std::cell::RefCell;
///
/// #[derive(Default)]
/// struct Parent {
///     child: Option<Rc<RefCell<Child>>>,
///     self_weak: Weak<RefCell<Parent>>,
/// }
///
/// impl Parent {
///     fn new() -> Rc<RefCell<Self>> {
///         let parent = Rc::new(RefCell::new(Parent::default()));
///         let self_weak = Rc::downgrade(&parent);
///         parent.borrow_mut().self_weak = self_weak;
///
///         parent
///     }
///
///     fn foo(&mut self) {
///         let self_weak = self.self_weak.clone();
///         let f = Box::new(move |a, b| {
///             if let Some(parent) = self_weak.upgrade() {
///                 // This will panic if cause_panic_for_parent is true
///                 parent.borrow_mut().handle(a, b);
///             }
///         });
///         self.child = Child::new(f);
///         if let Some(ref child) = self.child {
///             child.borrow_mut().foo();
///         }
///     }
///
///     fn handle(&mut self, a: String, b: Vec<u8>) {
///         // NOTE: Potential cause for panics. If this condition fires then Child might be
///         //       attempted to be borrowed again in the the current borrow hasn't ended for it,
///         //       as this is getting called because Child called the given callback (hence it's
///         //       borrow is still active).
///         if let Some(ref child) = self.child {
///             // This will panic if cause_panic_for_child is true
///             child.borrow_mut().handle(a, b);
///         }
///     }
/// }
///
/// struct Child {
///     f: Box<Fn(String, Vec<u8>)>,
/// }
///
/// impl Child {
///     fn new(f: Box<Fn(String, Vec<u8>)>) -> Option<Rc<RefCell<Self>>> {
///         // NOTE: Potential cause for panics. If this condition fires then Parent will be
///         //       attempted to be borrowed again in the callback though the current borrow hasn't
///         //       ended for it.
///         let cause_panic_for_parent = true;
///         if cause_panic_for_parent {
///             f(Default::default(), Default::default());
///             return None;
///         }
///         Some(Rc::new(RefCell::new(Child { f })))
///     }
///
///     fn foo(&mut self) {
///         // NOTE: This will eventually land the control in Parent::handle() which might cause
///         //       panic as Child is borrowed again (explained in Parent::handle() above).
///         let a = "queued-notifier docs".to_string();
///         let b = vec![99, 255, 43];
///
///         let cause_panic_for_child = true;
///         if cause_panic_for_child {
///             (self.f)(a, b);
///         }
///     }
///
///     fn handle(&mut self, a: String, b: Vec<u8>) {
///         println!("{},\t{:?}", a, b);
///     }
/// }
///
/// fn main() {
///     let parent = Parent::new();
///     parent.borrow_mut().foo();
/// }
/// ```
///
/// If all the callbacks were queued instead, the control would have to first return back to the
/// event loop ending all current borrows first. So now we can appreciate `QueuedNotifier` more
/// under these conditions and designs.
///
/// With `QueuedNotifier` the above code would change to:
///
/// # Examples
///
/// ```text
/// impl Parent {
///     // ...
///
///     fn foo(&mut self, ifc: &mut Interface) {
///         let self_weak = self.self_weak.clone();
///         let f = move |_ifc, _poll, (a, b)| {
///             if let Some(parent) = self_weak.upgrade() {
///                 // This will no longer cause panic
///                 parent.borrow_mut().handle(a, b);
///             }
///         };
///         self.child = Child::new(ifc, QueuedNotifier::new(f));
///
///         // ...
///     }
///
///     // ...
/// }
///
/// struct Child {
///     qnot: QueuedNotifier<(String, Vec<u8>)>,
/// }
///
/// impl Child {
///     fn new(
///         ifc: &mut Interface,
///         qnot: QueuedNotifier<(String, Vec<u8>)>
///     ) -> Option<Rc<RefCell<Self>>> {
///         let cause_panic_for_parent = true;
///         if cause_panic_for_parent {
///             qnot.notify(ifc, (Default::default(), Default::default()));
///             return None;
///         }
///         Some(Rc::new(RefCell::new(Child { f })))
///     }
/// ```
pub struct QueuedNotifier<UserData> {
    f: Option<Func<UserData>>,
}

impl<UserData> QueuedNotifier<UserData>
where
    UserData: 'static,
{
    /// Construct a `QueuedNotifier`. The observer is the given callback.
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce(&mut Interface, &Poll, UserData) + 'static,
    {
        let mut invaiant_f = Some(f);
        let f = Box::new(move |ifc: &mut Interface, poll: &Poll, user_data| {
            let f = unwrap!(invaiant_f.take());
            f(ifc, poll, user_data)
        });

        QueuedNotifier { f: Some(f) }
    }

    /// Notify the observer but not immediately; rather in the subsequent runs of the eventloop.
    pub fn notify(&mut self, ifc: &mut Interface, user_data: UserData) -> ::Res<()> {
        if let Some(f) = self.f.take() {
            QueuedNotifierImpl::initiate(ifc, user_data, f);
            Ok(())
        } else {
            Err(NatError::NotifierExpired)
        }
    }

    /// Notify the observer but not immediately; rather in the subsequent runs of the eventloop.
    /// It'll internally log a warning if any error is encountered instead of returning one.
    pub fn notify_or_warn(&mut self, ifc: &mut Interface, user_data: UserData) {
        if let Err(e) = self.notify(ifc, user_data) {
            warn!("Error notifying: {:?}", e);
        }
    }
}

struct QueuedNotifierImpl<UserData> {
    token: Token,
    invariant: Option<(UserData, Func<UserData>)>,
}

impl<UserData> QueuedNotifierImpl<UserData>
where
    UserData: 'static,
{
    fn initiate(ifc: &mut Interface, user_data: UserData, f: Func<UserData>) {
        let token = ifc.new_token();

        let state = Rc::new(RefCell::new(QueuedNotifierImpl {
            token,
            invariant: Some((user_data, f)),
        }));

        if let Err((_, e)) = ifc.insert_state(token, state) {
            warn!(
                "Could not queue the notification. Observer will never be notified: {:?}",
                e
            );
            return;
        }

        let m = NatMsg::new(move |ifc, poll| {
            if let Some(notifier) = ifc.state(token) {
                notifier.borrow_mut().terminate(ifc, poll);
            }
        });

        if let Err(e) = ifc.sender().send(m) {
            warn!(
                "Error in sending NatMsg. Queued Notification will never be invoked. Observer \
                 will never be notified: {:?}",
                e
            );
        }
    }
}

impl<UserData> NatState for QueuedNotifierImpl<UserData>
where
    UserData: 'static,
{
    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);

        let (user_data, mut f) = unwrap!(self.invariant.take());
        f(ifc, poll, user_data)
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
