use alloc::{collections::LinkedList, sync::Arc};
//use lazy_static::lazy_static;
use spin::Mutex;

use crate::task::{threads::futex_waiter, timeout_wake};

/* lazy_static! {
 *     pub static ref CHECK_LI: Mutex<LinkedList<(Arc<dyn Fn() -> bool>, Arc<dyn Fn()>)>> =
 *         Mutex::new(LinkedList::new());
 * } */
/// I do wish to keep this function for further use.
pub fn global_waiter() {
    timeout_wake();
    futex_waiter();
}
