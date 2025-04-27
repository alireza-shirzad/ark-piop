use crate::structs::TrackerID;

pub mod hp_interface;

/////////////////// Types ///////////////////
pub(crate) type VirtualPoly<F> = Vec<(F, Vec<TrackerID>)>;
