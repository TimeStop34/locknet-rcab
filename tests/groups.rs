//! Group lifecycle tests.
//!
//! Covers creation, invitations, joining, leaving, and the distinctions
//! between public and private groups. All tests assert on the wire-level
//! [`locknet_rcab::models::Group`] DTO returned by the low-level helpers.

mod common;

/// Creating a group only adds the creator as a member; participants receive
/// invites but are not auto-joined.
#[tokio::test]
async fn create_group_only_creator_is_member() {
    let alice = common::register_new("grp_create_a").await;
    let bob = common::register_new("grp_create_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let group = alice_low
        .groups()
        .create("CreateTest", false, None, vec![bob.session.user_id])
        .await
        .expect("create_group");

    assert_eq!(group.member_count, 1, "creator is the only member until accept");
    assert_eq!(group.created_by, alice.session.user_id);
    assert!(!group.is_public);
    assert!(group.public_id.is_none());
    let members = group.members.as_ref().expect("members present for creator");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].user_id, alice.session.user_id);

    let invites = bob_low.groups().invites().await.expect("invites");
    let inv = invites
        .iter()
        .find(|i| i.group_id == group.id)
        .expect("bob should see the invite");
    assert_eq!(inv.inviter_id, alice.session.user_id);
    assert_eq!(inv.group_name, "CreateTest");

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// Accepting an invite adds the member to both the server-side and client-side
/// member lists.
#[tokio::test]
async fn accept_invite_adds_member() {
    let alice = common::register_new("grp_accept_a").await;
    let bob = common::register_new("grp_accept_b").await;

    let group_id = common::setup_group_with_two(&alice, &bob, "AcceptTest").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    for (who, low) in [("alice", &alice_low), ("bob", &bob_low)] {
        let info = low.groups().info(group_id).await.expect("info");
        let ids: Vec<i64> = info
            .members
            .as_ref()
            .expect("members present for member")
            .iter()
            .map(|m| m.user_id)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        let mut expected = vec![alice.session.user_id, bob.session.user_id];
        expected.sort();
        assert_eq!(sorted, expected, "{who}: wrong member set");
        assert_eq!(info.member_count, 2, "{who}: member_count");
    }

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// Once an invite is accepted, it is consumed — a second accept fails with
/// `invite_not_found`.
#[tokio::test]
async fn accept_invite_twice_fails() {
    let alice = common::register_new("grp_acc2_a").await;
    let bob = common::register_new("grp_acc2_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let group = alice_low
        .groups()
        .create("Acc2", false, None, vec![bob.session.user_id])
        .await
        .expect("create");

    let invites = bob_low.groups().invites().await.expect("invites");
    let inv = invites.iter().find(|i| i.group_id == group.id).unwrap();

    bob_low.groups().accept_invite(inv.id).await.expect("accept #1");
    let err = bob_low.groups().accept_invite(inv.id).await.unwrap_err();
    common::assert_server_code(err, "invite_not_found");

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// Declining an invite consumes it and leaves the user outside the group.
#[tokio::test]
async fn decline_invite_works() {
    let alice = common::register_new("grp_decl_a").await;
    let bob = common::register_new("grp_decl_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let group = alice_low
        .groups()
        .create("Decline", false, None, vec![bob.session.user_id])
        .await
        .expect("create");

    let invites = bob_low.groups().invites().await.expect("invites");
    let inv = invites.iter().find(|i| i.group_id == group.id).unwrap();

    bob_low.groups().decline_invite(inv.id).await.expect("decline");

    let err = bob_low.groups().accept_invite(inv.id).await.unwrap_err();
    common::assert_server_code(err, "invite_not_found");

    let err = bob_low.groups().info(group.id).await.unwrap_err();
    common::assert_server_code(err, "group_not_found");

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// A member leaving a private group removes them from the member list, and
/// the remaining member sees the updated list.
#[tokio::test]
async fn member_leave_removes_from_group() {
    let alice = common::register_new("grp_leave_a").await;
    let bob = common::register_new("grp_leave_b").await;

    let group_id = common::setup_group_with_two(&alice, &bob, "Leave").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    bob_low.groups().leave(group_id).await.expect("bob leave");

    let err = bob_low.groups().info(group_id).await.unwrap_err();
    common::assert_server_code(err, "group_not_found");

    let info = alice_low.groups().info(group_id).await.expect("alice info");
    let ids: Vec<i64> = info.members.unwrap().iter().map(|m| m.user_id).collect();
    assert_eq!(ids, vec![alice.session.user_id]);

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// If the creator leaves, the group is deleted, all members are evicted, and
/// pending invites become invalid.
#[tokio::test]
async fn creator_leave_deletes_group() {
    let alice = common::register_new("grp_cleave_a").await;
    let bob = common::register_new("grp_cleave_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let group = alice_low
        .groups()
        .create("CreatorLeave", false, None, vec![bob.session.user_id])
        .await
        .expect("create");

    let invites = bob_low.groups().invites().await.expect("invites");
    let inv = invites.iter().find(|i| i.group_id == group.id).unwrap().clone();

    alice_low.groups().leave(group.id).await.expect("alice leave");

    let err = alice_low.groups().info(group.id).await.unwrap_err();
    common::assert_server_code(err, "group_not_found");

    let err = bob_low.groups().accept_invite(inv.id).await.unwrap_err();
    common::assert_server_code(err, "invite_not_found");

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// Creating a direct chat produces a private group with a generated name.
#[tokio::test]
async fn create_direct_creates_private_group() {
    let alice = common::register_new("grp_dir_a").await;
    let bob = common::register_new("grp_dir_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let direct = alice_low
        .groups()
        .create_direct(bob.session.user_id)
        .await
        .expect("create_direct");

    assert!(!direct.is_public);
    assert!(direct.public_id.is_none());
    assert_eq!(direct.member_count, 1, "only creator until accept");
    assert_eq!(direct.created_by, alice.session.user_id);

    let invites = bob_low.groups().invites().await.expect("invites");
    let inv = invites.iter().find(|i| i.group_id == direct.id).unwrap().clone();
    bob_low.groups().accept_invite(inv.id).await.expect("accept direct");

    let info = alice_low.groups().info(direct.id).await.expect("info");
    assert_eq!(info.member_count, 2);

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// Public groups are visible to non-members (but `members = None`), and
/// joining by `public_id` works exactly once.
#[tokio::test]
async fn public_group_join_and_already_member() {
    let alice = common::register_new("grp_pub_a").await;
    let bob = common::register_new("grp_pub_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let public_id = format!("&pub{}", common::unique_suffix());
    let group = alice_low
        .groups()
        .create("Public", true, Some(public_id.clone()), vec![])
        .await
        .expect("create public");

    assert!(group.is_public);
    assert_eq!(group.public_id.as_deref(), Some(public_id.as_str()));

    let seen = bob_low.groups().info(group.id).await.expect("info by non-member");
    assert!(seen.members.is_none(), "non-member must not see member list");
    assert_eq!(seen.member_count, 1);

    let joined = bob_low.groups().join(public_id.clone()).await.expect("join");
    assert_eq!(joined.id, group.id);

    let err = bob_low.groups().join(public_id.clone()).await.unwrap_err();
    common::assert_server_code(err, "already_member");

    let seen2 = bob_low.groups().info(group.id).await.expect("info member");
    assert!(seen2.members.is_some());
    assert_eq!(seen2.member_count, 2);

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// Private groups return `group_not_found` to non-members (this hides their
/// existence rather than revealing a 403).
#[tokio::test]
async fn private_group_not_visible_to_non_member() {
    let alice = common::register_new("grp_priv_a").await;
    let bob = common::register_new("grp_priv_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let group = alice_low
        .groups()
        .create("Private", false, None, vec![])
        .await
        .expect("create private");

    let err = bob_low.groups().info(group.id).await.unwrap_err();
    common::assert_server_code(err, "group_not_found");

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}

/// `get_groups` returns the groups the user is a member of.
#[tokio::test]
async fn get_groups_lists_member_groups() {
    let alice = common::register_new("grp_list_a").await;
    let bob = common::register_new("grp_list_b").await;

    let group_id = common::setup_group_with_two(&alice, &bob, "ListTest").await;

    let bob_low = bob.low();
    let groups = bob_low.groups().list().await.expect("list");
    assert!(
        groups.iter().any(|g| g.id == group_id),
        "bob's groups should contain {group_id}"
    );

    let mut alice = alice;
    let mut bob = bob;
    alice.client.disconnect().await.ok();
    bob.client.disconnect().await.ok();
}