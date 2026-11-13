
const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";

const users = new Map();

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

// Sign the username and message using the private key
function signMessage(username, message) {
  const data = JSON.stringify({ username, message });

  return crypto
    .sign("sha256", Buffer.from(data), privateKey)
    .toString("hex");
}

// Verify the signature using the sender's public key
function verifyMessage(username, message, signature, senderPublicKey) {
  const data = JSON.stringify({ username, message });

  return crypto.verify(
    "sha256",
    Buffer.from(data),
    senderPublicKey,
    Buffer.from(signature, "hex")
  );
}

socket.on("connect", () => {
  console.log("Connected to the server");
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));

  console.log(`There are currently ${users.size} users in the chat\n`);

  rl.question("Enter your username: ", (input) => {
    registeredUsername = input.trim();
    username = registeredUsername;

    console.log(`Welcome, ${username} to the chat`);

    // Register the actual RSA public key
    socket.emit("registerPublicKey", { username, publicKey });

    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        const match = message.match(/^!impersonate (\w+)$/);

        if (match) {
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          username = registeredUsername;
          console.log(`Now you are ${username}`);
        } else {
          const signature = signMessage(username, message);
          socket.emit("message", { username, message, signature });
        }
      }

      rl.prompt();
    });
  });
});

socket.on("newUser", (data) => {
  const { username: newUsername, publicKey } = data;

  users.set(newUsername, publicKey);
  console.log(`${newUsername} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const {username: senderUsername, message: senderMessage, signature,} = data;

  // Find the public key belonging to the claimed sender
  const senderPublicKey = users.get(senderUsername);

  // Verify the digital signature
  const isValid =
    senderPublicKey && signature &&
    verifyMessage(senderUsername, senderMessage, signature, senderPublicKey);

  if (!isValid) {
    console.log(`${senderUsername}: ${senderMessage}`);
    console.log("WARNING: this user is fake");
  } else if (senderUsername !== username) {
    console.log(`${senderUsername}: ${senderMessage}`);
  }

  rl.prompt();
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
