use isis_packet::*;

#[test]
pub fn json_test() {
    let prefix = prefix::IsisSubPrefixSid {
        flags: 0,
        algo: 0,
        sid: 100,
    };
    let tlv = prefix::IsisSubTlv::PrefixSid(prefix);
    let serialized = serde_json::to_string(&tlv).unwrap();
    println!("{}", serialized);
}
