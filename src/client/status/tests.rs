use super::*;
use crate::api::DeviceEntry;
use crate::storage::LinkStatus;

#[test]
fn client_status_serializes_to_expected_json_shape() {
    let status = ClientStatus {
        account_number: "+15555550100".to_string(),
        device_id: 3,
        aci: Some("11111111-1111-1111-1111-111111111111".to_string()),
        pni: Some("PNI:22222222-2222-2222-2222-222222222222".to_string()),
        link_status: LinkStatus::Linked,
        linked_devices: vec![DeviceEntry {
            id: 1,
            name: Some("name1".to_string()),
            created_ms: Some(1000),
            last_seen_ms: Some(2000),
        }],
    };
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["account_number"], "+15555550100");
    assert_eq!(json["device_id"], 3);
    assert_eq!(json["aci"], "11111111-1111-1111-1111-111111111111");
    assert_eq!(json["pni"], "PNI:22222222-2222-2222-2222-222222222222");
    assert_eq!(json["link_status"], "linked");
    let devices = json["linked_devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["id"], 1);
    assert_eq!(devices[0]["name"], "name1");
    assert_eq!(devices[0]["created_ms"], 1000);
    assert_eq!(devices[0]["last_seen_ms"], 2000);
}

#[test]
fn client_status_serializes_partially_linked_as_snake_case() {
    let status = ClientStatus {
        account_number: "+15555550100".to_string(),
        device_id: 2,
        aci: None,
        pni: None,
        link_status: LinkStatus::IdentityPersisted,
        linked_devices: Vec::new(),
    };
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["link_status"], "identity_persisted");
    assert!(json["aci"].is_null());
    assert!(json["pni"].is_null());
    assert_eq!(json["linked_devices"].as_array().unwrap().len(), 0);
}
