mod frontrunning;
mod integer_overflow;
mod missing_deposit_check;
mod missing_gas_callback;
mod missing_private;
mod promise_reentrancy;
mod self_callback;
mod signer_vs_predecessor;
mod storage_staking;
mod unguarded_storage_unregister;
mod unhandled_promise;
mod unsafe_storage_keys;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(promise_reentrancy::PromiseReentrancyDetector));
    detectors.push(Box::new(signer_vs_predecessor::SignerVsPredecessorDetector));
    detectors.push(Box::new(storage_staking::StorageStakingDetector));
    detectors.push(Box::new(unhandled_promise::UnhandledPromiseDetector));
    detectors.push(Box::new(integer_overflow::IntegerOverflowDetector));
    detectors.push(Box::new(missing_private::MissingPrivateDetector));
    detectors.push(Box::new(self_callback::SelfCallbackDetector));
    detectors.push(Box::new(frontrunning::FrontrunningDetector));
    detectors.push(Box::new(unsafe_storage_keys::UnsafeStorageKeysDetector));
    detectors.push(Box::new(missing_deposit_check::MissingDepositCheckDetector));
    detectors.push(Box::new(
        unguarded_storage_unregister::UnguardedStorageUnregisterDetector,
    ));
    detectors.push(Box::new(missing_gas_callback::MissingGasCallbackDetector));
}
