const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue, Timestamp } = require("firebase-admin/firestore");
const crypto = require("node:crypto");
const { promisify } = require("node:util");

initializeApp();
const db = getFirestore();
const pbkdf2 = promisify(crypto.pbkdf2);
const REGION = "asia-south1";
const PIN_ITERATIONS = 210000;
const PIN_LENGTH = 6;
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 20;

function normalizeName(value) {
  return String(value || "").normalize("NFKC").trim().replace(/\s+/g, " ").toLocaleLowerCase("en");
}

async function requireAdmin(request) {
  if (!request.auth) throw new HttpsError("unauthenticated", "Please sign in first.");
  const staff = await db.collection("staff").doc(request.auth.uid).get();
  if (!staff.exists || staff.data().active !== true || staff.data().role !== "admin") {
    throw new HttpsError("permission-denied", "Active admin access is required.");
  }
}

async function hashPin(pin, salt) {
  const derived = await pbkdf2(pin, salt, PIN_ITERATIONS, 32, "sha256");
  return derived.toString("hex");
}

function validPin(pin) {
  return typeof pin === "string" && /^\d{6}$/.test(pin);
}

async function consumeAttempt(request) {
  const ip = String(request.rawRequest?.ip || "unknown");
  const ipKey = crypto.createHash("sha256").update(ip).digest("hex");
  const ref = db.collection("parentPortalRateLimits").doc(ipKey);
  const now = Date.now();

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? snap.data() : {};
    const start = data.windowStartedAt?.toMillis?.() || 0;
    const count = start > now - WINDOW_MS ? Number(data.count || 0) : 0;
    if (count >= MAX_ATTEMPTS) {
      throw new HttpsError("resource-exhausted", "Too many attempts. Please try again in 15 minutes.");
    }
    tx.set(ref, {
      count: count + 1,
      windowStartedAt: start > now - WINDOW_MS ? data.windowStartedAt : Timestamp.fromMillis(now),
      updatedAt: FieldValue.serverTimestamp()
    });
  });
}

exports.setParentPin = onCall({ region: REGION, enforceAppCheck: false }, async (request) => {
  await requireAdmin(request);
  const studentId = String(request.data?.studentId || "").trim();
  const pin = request.data?.pin;
  if (!studentId || !validPin(pin)) {
    throw new HttpsError("invalid-argument", "Enter a Student ID and a 6-digit PIN.");
  }

  const matches = await db.collection("students").where("studentId", "==", studentId).limit(2).get();
  if (matches.empty) throw new HttpsError("not-found", "No student found with that Student ID.");
  if (matches.size !== 1) throw new HttpsError("failed-precondition", "Student ID is not unique. Correct the student records first.");
  const studentDoc = matches.docs[0];
  const salt = crypto.randomBytes(16).toString("hex");
  const pinHash = await hashPin(pin, salt);

  await db.collection("parentAccess").doc(studentDoc.id).set({
    studentDocId: studentDoc.id,
    studentId,
    pinSalt: salt,
    pinHash,
    pinIterations: PIN_ITERATIONS,
    updatedAt: FieldValue.serverTimestamp(),
    updatedBy: request.auth.uid
  });
  return { ok: true, message: "Parent PIN saved." };
});

exports.parentStudentLookup = onCall({ region: REGION, enforceAppCheck: false }, async (request) => {
  await consumeAttempt(request);
  const name = String(request.data?.name || "").trim();
  const pin = request.data?.pin;
  if (!name || name.length > 120 || !validPin(pin)) {
    throw new HttpsError("invalid-argument", "Enter the child's full name and 6-digit Parent PIN.");
  }

  const wanted = normalizeName(name);
  const studentSnap = await db.collection("students").get();
  const matches = studentSnap.docs.filter((doc) => normalizeName(doc.data().name) === wanted);
  for (const studentDoc of matches) {
    const accessSnap = await db.collection("parentAccess").doc(studentDoc.id).get();
    if (!accessSnap.exists) continue;
    const access = accessSnap.data();
    const candidate = await hashPin(pin, access.pinSalt);
    const a = Buffer.from(candidate, "hex");
    const b = Buffer.from(String(access.pinHash || ""), "hex");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) continue;

    const s = studentDoc.data();
    const attendanceSnap = await db.collection("attendance").orderBy("date", "desc").limit(180).get();
    const attendance = [];
    for (const record of attendanceSnap.docs) {
      const row = record.data();
      const status = row.records && row.records[studentDoc.id];
      if (status) {
        attendance.push({
          date: String(row.date || ""),
          classSection: String(row.classSection || ""),
          status: String(status)
        });
      }
    }
    return {
      student: {
        studentId: String(s.studentId || ""),
        name: String(s.name || ""),
        classSection: String(s.classSection || ""),
        roll: String(s.roll || ""),
        academicYear: String(s.academicYear || ""),
        status: String(s.status || ""),
        photoURL: String(s.photoURL || "")
      },
      attendance
    };
  }

  throw new HttpsError("not-found", "Name or Parent PIN did not match. Please check and try again.");
});
