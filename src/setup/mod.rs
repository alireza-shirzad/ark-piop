//////// Modules /////////
pub(crate) mod errors;
pub mod structs;

//////// Imports /////////
use crate::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, load_or_generate_srs},
};
use ark_ff::PrimeField;
use ark_std::cfg_iter;

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::{collections::BTreeMap, env::current_dir, marker::PhantomData, path::PathBuf, sync::Arc};
use structs::{SNARKPk, SNARKVk};
use tracing::instrument;
//////// Body /////////

/// A key generator struct
/// It uses the static information about the table, like the maximum size, etc
/// and generates the proving and verifying keys
pub struct KeyGenerator<B: SnarkBackend> {
    log_size: usize,
    srs_path: PathBuf,
    _phantom: std::marker::PhantomData<B>,
}

impl<B> Default for KeyGenerator<B>
where
    B: SnarkBackend,
{
    fn default() -> Self {
        Self {
            log_size: 23,
            srs_path: current_dir().unwrap().join("..").join("srs"),
            _phantom: PhantomData,
        }
    }
}

impl<B> KeyGenerator<B>
where
    B: SnarkBackend,
{
    /// Creates a new `KeyGenerator` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the log of number of table maximum size.
    pub fn with_num_mv_vars(mut self, log_size: usize) -> Self {
        self.log_size = log_size;
        self
    }

    /// Sets the path to the SRS file.
    pub fn with_srs_path(mut self, srs_path: PathBuf) -> Self {
        self.srs_path = srs_path;
        self
    }

    /// Generate the proving and verifying keys for the system based on the
    /// configuration in the `KeyGenerator` struct
    #[allow(clippy::type_complexity)]
    #[instrument(level = "debug", skip(self))]
    pub fn gen_keys(self) -> SnarkResult<(SNARKPk<B>, SNARKVk<B>)> {
        // Load or generate the multivariate SRS
        let mv_srs = load_or_generate_srs::<B::F, B::MvPCS>(
            &self.srs_path.join(format!("mv_{}.srs", self.log_size)),
            self.log_size,
        );
        // Load or generate the univariate SRS
        let uv_srs = load_or_generate_srs::<B::F, B::UvPCS>(
            &self.srs_path.join(format!("uv_{}.srs", 1 << self.log_size)),
            1 << self.log_size,
        );
        // Trim the multivariate srs
        let (mv_pcs_param_raw, mv_v_param) = B::MvPCS::trim(&mv_srs, None, Some(self.log_size))?;
        // Trim the univariate srs
        let (uv_pcs_param_raw, uv_v_param) =
            B::UvPCS::trim(&uv_srs, Some(1 << self.log_size), None)?;

        let mv_pcs_param = Arc::new(mv_pcs_param_raw);
        let uv_pcs_param = Arc::new(uv_pcs_param_raw);

        // Assembling the indexed MLEs
        // let indexed_tracked_polys: BTreeMap<String, MLE<F>> = Self::gen_indexed_tracked_polys();
        let indexed_tracked_polys: BTreeMap<String, MLE<B::F>> = BTreeMap::new();
        // Assemble the indexed comitments
        let indexed_coms: BTreeMap<String, <B::MvPCS as PCS<B::F>>::Commitment> =
            Self::gen_indexed_coms(&indexed_tracked_polys, mv_pcs_param.as_ref());

        // Assemble the verifying key
        let vk = SNARKVk {
            log_size: self.log_size,
            mv_pcs_vk: mv_v_param,
            uv_pcs_vk: uv_v_param,
            indexed_coms,
        };
        // Assemble the proving key
        let pk = SNARKPk {
            log_size: self.log_size,
            mv_pcs_param,
            uv_pcs_param,
            indexed_tracked_polys,
            vk: vk.clone(),
        };

        Ok((pk, vk))
    }

    /// Generate the indexed MLEs, these MLEs are produced in the setup and sent
    /// as a part of the pk to the prover
    // ]
    // fn gen_indexed_tracked_polys() -> BTreeMap<String, MLE<F>> {
    //     let range_mles: BTreeMap<DataType, MLE<F>> = DataType::gen_range_polys();
    //     let indexed_tracked_polys: BTreeMap<String, MLE<F>> = cfg_iter!(range_mles)
    //         .map(|(key, mle)| (key.to_string(), mle.clone()))
    //         .collect();
    //     indexed_tracked_polys
    // }
    /// Generate the indexed comitments, these comitments are produced in the
    /// setup and sent as a part of the vk to the verifier
    fn gen_indexed_coms(
        indexed_tracked_polys: &BTreeMap<String, MLE<B::F>>,
        mv_pcs_param: &<B::MvPCS as PCS<B::F>>::ProverParam,
    ) -> BTreeMap<String, <B::MvPCS as PCS<B::F>>::Commitment> {
        cfg_iter!(indexed_tracked_polys)
            .map(|(data_type, poly)| {
                let comm = <B::MvPCS as PCS<B::F>>::commit(
                    mv_pcs_param,
                    &std::sync::Arc::new(poly.clone()),
                )
                .unwrap();
                (data_type.clone(), comm)
            })
            .collect::<BTreeMap<String, <B::MvPCS as PCS<B::F>>::Commitment>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DefaultSnarkBackend,
        pcs::{kzg10::KZG10, pst13::PST13},
    };
    #[test]
    fn test_keygen() {
        let key_generator = KeyGenerator::<DefaultSnarkBackend>::new().with_num_mv_vars(16);
        let (_pk, _vk) = key_generator.gen_keys().unwrap();
    }
}
