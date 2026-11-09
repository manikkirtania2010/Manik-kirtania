const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const { test, before, after, beforeEach } = require("node:test");
const fs = require("node:fs");

let testEnv;
const PROJECT_ID = "demo-no-project";
const ALICE_UID = "player_alice_123";
const BOB_UID = "player_bob_456";
const CHARLIE_UID = "player_charlie_789";
const ADMIN_EMAIL = "kirtaniamanik2010@gmail.com";
const ADMIN_UID = "super_admin_manik";

const [emulatorHost, emulatorPortStr] = (process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8085").split(":");
const emulatorPort = parseInt(emulatorPortStr, 10);

before(async () => {
  const rules = fs.readFileSync("./firestore.rules", "utf8");
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules,
      host: emulatorHost,
      port: emulatorPort,
    },
  });
});

after(async () => {
  if (testEnv) {
    await testEnv.cleanup();
  }
});

beforeEach(async () => {
  if (testEnv) {
    await testEnv.clearFirestore();
  }
});

// Helper contexts
function getPlayerAlice() {
  return testEnv.authenticatedContext(ALICE_UID, { email: "alice@example.com" }).firestore();
}

function getPlayerBob() {
  return testEnv.authenticatedContext(BOB_UID, { email: "bob@example.com" }).firestore();
}

function getPlayerCharlie() {
  return testEnv.authenticatedContext(CHARLIE_UID, { email: "charlie@example.com" }).firestore();
}

function getSuperAdmin() {
  return testEnv.authenticatedContext(ADMIN_UID, { email: ADMIN_EMAIL }).firestore();
}

// ==========================================
// TASK 9 TESTING SCENARIOS
// ==========================================

test("1. Regular player cannot modify tournament data", async () => {
  const alice = getPlayerAlice();
  await assertFails(alice.collection("tournaments").doc("T-TEST-1").set({
    titleEn: "Hacked Tournament",
    entryFee: 0,
    totalSlots: 100,
  }));
});

test("2. Regular player cannot modify leaderboard scores", async () => {
  const alice = getPlayerAlice();
  await assertFails(alice.collection("leaderboard").doc("LEAD-1").set({
    userId: ALICE_UID,
    playerName: "Alice",
    rank: 1,
    totalEarnings: 999999,
  }));
});

test("3. Player A cannot read Player B's private wallet", async () => {
  // Seed Bob's wallet via admin
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context.firestore().collection("users").doc(BOB_UID).collection("wallet").doc("main").set({
      userId: BOB_UID,
      depositBalance: 500,
      winningBalance: 1200,
    });
    await context.firestore().collection("wallets").doc(BOB_UID).set({
      userId: BOB_UID,
      depositBalance: 500,
      winningBalance: 1200,
    });
  });

  const alice = getPlayerAlice();
  await assertFails(alice.collection("users").doc(BOB_UID).collection("wallet").doc("main").get());
  await assertFails(alice.collection("wallets").doc(BOB_UID).get());
});

test("4. Player cannot increase their wallet balance", async () => {
  const alice = getPlayerAlice();
  // Attempt to write to user's own wallet subcollection
  await assertFails(alice.collection("users").doc(ALICE_UID).collection("wallet").doc("main").set({
    userId: ALICE_UID,
    depositBalance: 99999,
    winningBalance: 99999,
  }));
  // Attempt to write to legacy wallets collection
  await assertFails(alice.collection("wallets").doc(ALICE_UID).set({
    userId: ALICE_UID,
    depositBalance: 99999,
  }));
});

test("5. Player cannot approve their own withdrawal or deposit", async () => {
  const alice = getPlayerAlice();
  // Cannot create withdrawal directly in APPROVED status
  await assertFails(alice.collection("withdrawals").doc("W-100").set({
    userId: ALICE_UID,
    amount: 500,
    method: "UPI",
    payoutDestination: "alice@upi",
    status: "APPROVED",
  }));

  // Seed pending withdrawal
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context.firestore().collection("withdrawals").doc("W-101").set({
      userId: ALICE_UID,
      amount: 300,
      method: "UPI",
      payoutDestination: "alice@upi",
      status: "PENDING",
    });
  });

  // Cannot update status to APPROVED
  await assertFails(alice.collection("withdrawals").doc("W-101").update({
    status: "APPROVED",
    approvedBy: ALICE_UID,
  }));
});

test("6. Player cannot modify or read admin audit logs", async () => {
  const alice = getPlayerAlice();
  await assertFails(alice.collection("adminAuditLogs").doc("LOG-1").set({
    action: "ROOM_PUBLISHED",
    targetId: "T-101",
    performedBy: ALICE_UID,
  }));
  await assertFails(alice.collection("adminAuditLogs").doc("LOG-1").get());
});

test("7. Player cannot modify their own or another player's ban status or admin role", async () => {
  // Seed Alice user profile
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context.firestore().collection("users").doc(ALICE_UID).set({
      uid: ALICE_UID,
      displayName: "Alice",
      email: "alice@example.com",
      isAdmin: false,
      isBanned: false,
      accountStatus: "ACTIVE",
    });
  });

  const alice = getPlayerAlice();
  // Attempt privilege escalation to admin
  await assertFails(alice.collection("users").doc(ALICE_UID).update({
    isAdmin: true,
  }));
  // Attempt to change account status or ban
  await assertFails(alice.collection("users").doc(ALICE_UID).update({
    accountStatus: "PERMANENTLY_BANNED",
    isBanned: true,
  }));
});

test("8. Unauthorized users cannot access private incident reports", async () => {
  // Report by Alice against Bob
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context.firestore().collection("incidentReports").doc("REP-101").set({
      reportedByUserId: ALICE_UID,
      reportedUserId: BOB_UID,
      tournamentId: "T-LW-101",
      reason: "Cheating / Aimbot",
      status: "PENDING",
    });
  });

  const charlie = getPlayerCharlie();
  // Charlie is an outsider (neither reporter nor accused)
  await assertFails(charlie.collection("incidentReports").doc("REP-101").get());

  // Reporter Alice can read
  const alice = getPlayerAlice();
  await assertSucceeds(alice.collection("incidentReports").doc("REP-101").get());

  // Accused Bob can read
  const bob = getPlayerBob();
  await assertSucceeds(bob.collection("incidentReports").doc("REP-101").get());
});

test("9. Authorized Super Admin operations succeed", async () => {
  const admin = getSuperAdmin();

  // 1. Admin creates tournament
  await assertSucceeds(admin.collection("tournaments").doc("T-ADMIN-1").set({
    id: "T-ADMIN-1",
    titleEn: "Admin Mega Clash",
    entryFee: 50,
    totalSlots: 48,
    paidParticipantUids: [ALICE_UID],
  }));

  // 2. Admin creates secure room credentials
  await assertSucceeds(admin.collection("tournaments").doc("T-ADMIN-1").collection("private_room").doc("credentials").set({
    tournamentId: "T-ADMIN-1",
    roomId: "ROOM_777",
    roomPassword: "PASS_777",
  }));

  // 3. Admin updates leaderboard
  await assertSucceeds(admin.collection("leaderboard").doc("LEAD-1").set({
    userId: ALICE_UID,
    playerName: "Alice",
    rank: 1,
    totalWins: 5,
  }));

  // 4. Admin writes audit log
  await assertSucceeds(admin.collection("adminAuditLogs").doc("LOG-100").set({
    action: "PRIZE_SETTLED",
    targetId: "T-ADMIN-1",
    performedBy: ADMIN_EMAIL,
  }));

  // 5. Admin updates wallet balance
  await assertSucceeds(admin.collection("users").doc(ALICE_UID).collection("wallet").doc("main").set({
    userId: ALICE_UID,
    depositBalance: 100,
    winningBalance: 200,
  }));
});

test("10. Legitimate player operations succeed", async () => {
  const alice = getPlayerAlice();

  // 1. Alice registers her user profile with non-privileged defaults
  await assertSucceeds(alice.collection("users").doc(ALICE_UID).set({
    uid: ALICE_UID,
    displayName: "Alice Pro",
    email: "alice@example.com",
    freeFireUID: "99881122",
    freeFireName: "ALICE_FF",
    freeFireLevel: 25,
    isAdmin: false,
    isBanned: false,
    accountStatus: "ACTIVE",
  }));

  // 2. Alice updates her permitted profile fields
  await assertSucceeds(alice.collection("users").doc(ALICE_UID).update({
    freeFireName: "ALICE_BOSS",
    avatarId: 3,
  }));

  // 3. Alice reads tournament schedule
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context.firestore().collection("tournaments").doc("T-PUBLIC-1").set({
      id: "T-PUBLIC-1",
      titleEn: "Public Battle Royale",
      entryFee: 20,
      totalSlots: 40,
      paidParticipantUids: [ALICE_UID],
    });
    await context.firestore().collection("tournaments").doc("T-PUBLIC-1").collection("private_room").doc("credentials").set({
      roomId: "992211",
      roomPassword: "3322",
    });
  });
  await assertSucceeds(alice.collection("tournaments").doc("T-PUBLIC-1").get());

  // 4. Alice (paid participant) can read room credentials
  await assertSucceeds(alice.collection("tournaments").doc("T-PUBLIC-1").collection("private_room").doc("credentials").get());

  // 5. Alice submits a deposit request in PENDING status
  await assertSucceeds(alice.collection("addMoneyRequests").doc("DEP-ALICE-1").set({
    userId: ALICE_UID,
    amount: 100,
    utrNumber: "UTR12345678",
    paymentMethod: "UPI",
    status: "PENDING",
  }));

  // 6. Alice submits an incident report in PENDING status
  await assertSucceeds(alice.collection("incidentReports").doc("REP-ALICE-1").set({
    reportedByUserId: ALICE_UID,
    reportedUserId: BOB_UID,
    tournamentId: "T-PUBLIC-1",
    reason: "Speed hack",
    status: "PENDING",
  }));
});
