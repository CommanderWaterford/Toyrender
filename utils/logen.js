const fs = require("fs");
const path = require("path");

const LOG_DIR = path.join(__dirname, "..", "_logs");
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const USER_LOG_PATH = path.join(LOG_DIR, "user-activity.ndjson");
const userLogStream = fs.createWriteStream(USER_LOG_PATH, { flags: "a" });

const closeStream = () => {
  if (!userLogStream.destroyed) {
    userLogStream.end();
  }
};

process.on("exit", closeStream);
process.on("SIGINT", closeStream);
process.on("SIGTERM", closeStream);

function writeEvent(event, entry) {
  try {
    const payload = {
      ts: new Date().toISOString(),
      event,
      ...entry,
    };
    userLogStream.write(JSON.stringify(payload) + "\n");
  } catch (err) {
    console.error("Failed to write user log", err);
  }
}

function logRegistration(entry) {
  writeEvent("user_registered", entry);
}

function logRegistrationSuccess(entry) {
  writeEvent("register_success", entry);
}

function logRegistrationFailure(entry) {
  writeEvent("register_failure", entry);
}

function logAuthSuccess(entry) {
  writeEvent("auth_success", entry);
}

function logAuthFailure(entry) {
  writeEvent("auth_failure", entry);
}

module.exports = {
  logRegistration,
  logRegistrationSuccess,
  logRegistrationFailure,
  logAuthSuccess,
  logAuthFailure,
};
