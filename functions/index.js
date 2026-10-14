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
    if (count >= MAX_ATTEMPTS) throw new HttpsError("resource-exhausted", "Too many attempts. Please try again in 15 minutes.");
    tx.set(ref, { count: count + 1, windowStartedAt: start > now - WINDOW_MS ? data.windowStartedAt : Timestamp.fromMillis(now), updatedAt: FieldValue.serverTimestamp() });
  });
}
exports.parentStudentLookup = onCall({ region: REGION, enforceAppCheck: false }, async (request) => {
  await consumeAttempt(request);
  const name = String(request.data?.name || "").trim();
  if (!name || name.length > 120) throw new HttpsError("invalid-argument", "Enter the child's exact full name.");
  const wanted = normalizeName(name);
  const studentSnap = await db.collection("students").get();
  const matches = studentSnap.docs.filter((doc) => normalizeName(doc.data().name) === wanted);
  if (matches.length !== 1) throw new HttpsError("not-found", "No unique student record found for that exact name.");
  const studentDoc = matches[0];
  const s = studentDoc.data();
  const attendanceSnap = await db.collection("attendance").orderBy("date", "desc").limit(180).get();
  const attendance = [];
  for (const record of attendanceSnap.docs) {
    const row = record.data();
    const status = row.records && row.records[studentDoc.id];
    if (status) attendance.push({ date: String(row.date || ""), classSection: String(row.classSection || ""), status: String(status) });
  }
  return { student: { studentId: String(s.studentId || ""), name: String(s.name || ""), classSection: String(s.classSection || ""), roll: String(s.roll || ""), academicYear: String(s.academicYear || ""), status: String(s.status || ""), photoURL: String(s.photoURL || "") }, attendance };
});
