use fvm_shared::econ::TokenAmount;
use fvm_shared::sector::StoragePower;
use num_traits::zero;
use recall_fil_actor_miner::initial_pledge_for_power;
use recall_fil_actors_runtime::reward::FilterEstimate;

macro_rules! my_const {
    ($name:ident, $ret_type:ty, $value:expr) => {
        fn $name() -> $ret_type {
            $value
        }
    };
}

my_const!(epoch_target_reward, TokenAmount, zero());
my_const!(qa_sector_power, StoragePower, StoragePower::from(1u64 << 36));
my_const!(network_qa_power, StoragePower, StoragePower::from(1u64 << 10));
my_const!(power_rate_of_change, StoragePower, StoragePower::from(1u64 << 10));
my_const!(
    reward_estimate,
    FilterEstimate,
    FilterEstimate::new(epoch_target_reward().atto().clone(), zero())
);
my_const!(
    power_estimate,
    FilterEstimate,
    FilterEstimate::new(network_qa_power(), power_rate_of_change())
);
my_const!(circulating_supply, TokenAmount, TokenAmount::from_whole(1));

// Pre-ramp where 'baseline power' dominates
#[test]
fn initial_pledge_pre_ramp_negative() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        -100,
        100,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1500).div_floor(10000),
        initial_pledge
    );
}

#[test]
fn initial_pledge_zero_ramp_duration() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        0,
        0,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1950).div_floor(10000),
        initial_pledge
    );

    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        10,
        0,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1950).div_floor(10000),
        initial_pledge
    );
}

// Pre-ramp where 'baseline power' dominates
#[test]
fn initial_pledge_pre_ramp() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        0,
        100,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1500).div_floor(10000),
        initial_pledge
    );
}

// On-ramp where 'baseline power' is at 85% and `simple power` is at 15%.
#[test]
fn initial_pledge_on_ramp_mid() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        50,
        100,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1725).div_floor(10000),
        initial_pledge
    );
}

// After-ramp where 'baseline power' is at 70% and `simple power` is at 30%.
#[test]
fn initial_pledge_after_ramp() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        150,
        100,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1950).div_floor(10000),
        initial_pledge
    );
}

// On-ramp where 'baseline power' has reduced effect (97%).
#[test]
fn initial_pledge_on_ramp_early() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        10,
        100,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1545).div_floor(10000),
        initial_pledge
    );
}

// On-ramp, first epoch, pledge should be 97% 'baseline' + 3% simple.
#[test]
fn initial_pledge_on_ramp_step() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        1,
        10,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1545).div_floor(10000),
        initial_pledge
    );
}

// Validate pledges 1 epoch before and after ramp start.
#[test]
fn initial_pledge_ramp_edges() {
    let initial_pledge_before_ramp = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        -1,
        10,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1500).div_floor(10000),
        initial_pledge_before_ramp
    );

    let initial_pledge_at_ramp = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        0,
        10,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1500).div_floor(10000),
        initial_pledge_at_ramp
    );

    let initial_pledge_on_ramp = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        1,
        10,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1545).div_floor(10000),
        initial_pledge_on_ramp
    );
}

// Post-ramp where 'baseline power' has reduced effect (70%).
#[test]
fn initial_pledge_post_ramp() {
    let initial_pledge = initial_pledge_for_power(
        &qa_sector_power(),
        &StoragePower::from(1u64 << 37),
        &reward_estimate(),
        &power_estimate(),
        &circulating_supply(),
        500,
        100,
    );
    assert_eq!(
        TokenAmount::from_atto(1) + TokenAmount::from_whole(1950).div_floor(10000),
        initial_pledge
    );
}
