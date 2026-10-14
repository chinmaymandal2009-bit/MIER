const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue, Timestamp } = require("firebase-admin/firestore");
const crypto = require("node:crypto");

initializeApp();
const db = getFirestore();
const REGION = "asia-south1";
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

function normalizeName(value) {
  return String(value || "").normalize("NFKC").trim().replace(/\s+/g, " ").toLocaleLowerCase("en");
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

exports.parentStudentLookup = onCall({ region: REGION, enforceAppCheck: false }, async (request) => {
  await consumeAttempt(request);
  const name = String(request.data?.name || "").trim();
  const classSection = String(request.data?.classSection || "").trim();
  const roll = String(request.data?.roll || "").trim();
  if (!name || name.length > 120 || !classSection || classSection.length > 80 || !roll || roll.length > 20) {
    throw new HttpsError("invalid-argument", "Enter the exact name, class/section, and roll number.");
  }

  const wanted = normalizeName(name);
  const wantedClass = normalizeName(classSection);
  const wantedRoll = normalizeName(roll);
  const studentSnap = await db.collection("students").get();
  const matches = studentSnap.docs.filter((doc) => {
    const s = doc.data();
    return normalizeName(s.name) === wanted
      && normalizeName(s.classSection) === wantedClass
      && normalizeName(s.roll) === wantedRoll;
  });

  // These fields help narrow the record but are not strong identity verification.
  if (matches.length !== 1) {
    throw new HttpsError("not-found", "No unique student record found for that exact name, class, and roll.");
  }

  const s = matches[0].data();
  // Deliberately return only basic information. No attendance, student ID, roll, photo, or private records.
  return {
    student: {
      name: String(s.name || ""),
      classSection: String(s.classSection || ""),
      academicYear: String(s.academicYear || "")
    }
  };
});
