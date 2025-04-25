#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Get the path to the .pyz file
const pyzPath = path.join(__dirname, '../dist/mcp-scan.pyz');

// Check if Python is available
function checkPython() {
  return new Promise((resolve, reject) => {
    const python = spawn('python3', ['--version']);

    python.on('close', (code) => {
      if (code === 0) {
        resolve(true);
      } else {
        reject(new Error('Python 3 is required but not found. Please install Python 3.'));
      }
    });

    python.on('error', () => {
      reject(new Error('Python 3 is required but not found. Please install Python 3.'));
    });
  });
}

// Run the .pyz file with Python
async function runPyz() {
  try {
    await checkPython();

    if (!fs.existsSync(pyzPath)) {
      console.error('MCP Scan executable not found!');
      process.exit(1);
    }

    // Get all arguments passed to the script
    const args = process.argv.slice(2);

    // Spawn a Python process to run the .pyz file with the provided arguments
    const mcp = spawn('python3', [pyzPath, ...args], {
      stdio: 'inherit' // This makes the output visible in the terminal
    });

    mcp.on('close', (code) => {
      process.exit(code);
    });
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

runPyz();
