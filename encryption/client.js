
const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
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

// Encrypt a message using the recipient's public key
function encryptMessage(message, recipientPublicKey) {
  return crypto.publicEncrypt(
    {
      key: recipientPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(message)
  ).toString("base64");
}

// Decrypt a message using our own private key
function decryptMessage(encryptedMessage) {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encryptedMessage, "base64")
  ).toString();
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input.trim();

    console.log(`Welcome, ${username} to the chat`);

    // Register the actual RSA public key
    socket.emit("registerPublicKey", {
      username,
      publicKey,
    });

    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        const match = message.match(/^!secret (\w+)$/);

        if (match) {
          targetUsername = match[1];
          console.log(`Now secretly chatting with ${targetUsername}`);
        } else if (message.match(/^!exit$/)) {
          console.log(
            `No more secretly chatting with ${targetUsername}`
          );
          targetUsername = "";
        } else {
          if (targetUsername) {
            // Find the recipient's public key
            const recipientPublicKey = users.get(targetUsername);

            if (!recipientPublicKey) {
              console.log(
                `User ${targetUsername} not found or has no registered public key`
              );
            } else {
              // Encrypt the message using the recipient's public key
              const encryptedMessage = encryptMessage(
                message,
                recipientPublicKey
              );

              socket.emit("message", {
                username,
                message: encryptedMessage,
                targetUsername,
                encrypted: true,
              });
            }
          } else {
            // Send a normal, unencrypted message
            socket.emit("message", {
              username,
              message,
              encrypted: false,
            });
          }
        }
      }

      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));

  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUsername, publicKey } = data;

  users.set(newUsername, publicKey);

  console.log(`${newUsername} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const {
    username: senderUsername,
    message: senderMessage,
    targetUsername: recipientUsername,
    encrypted,
  } = data;

  if (senderUsername !== username) {
    if (encrypted && recipientUsername === username) {
      // Only the intended recipient decrypts the message
      try {
        const decryptedMessage = decryptMessage(senderMessage);

        console.log(`${senderUsername}: ${decryptedMessage}`);
      } catch (error) {
        console.log("Unable to decrypt the message.");
      }
    } else if (encrypted) {
      // Other users see the ciphertext
      console.log(`${senderUsername}: ${senderMessage}`);
    } else {
      // Display normal, unencrypted messages
      console.log(`${senderUsername}: ${senderMessage}`);
    }
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