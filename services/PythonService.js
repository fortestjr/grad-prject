
import { spawn } from "child_process";

import dbConnection from "../db/db.js";
import { rejects } from "assert";
const db = await dbConnection();

export class PythonService {
    constructor(timeout) {
        this.timeout = timeout || 300000000;
    }

    // This function should return the path to the script

    async #getScriptPath(scriptName) {
        // Fetch the script from the database
        const script = await db.get(
            "select path from SecurityTools where name = ?",
            [scriptName]
        )
        // Check if the script exists
        console.log(`Query result:`, script)
        if (!script) {
            throw new Error(`Script ${scriptName} not found in the database`);
        }
        return script.path
    }

    async #runPythonScript(scriptPath, args = []) {
        let pythonProcess;
        let timeoutId;
        
        try {
            // const scriptPath = await this.#getScriptPath(scriptName);
            const controller = new AbortController();
            timeoutId = setTimeout(() => controller.abort(), this.timeout);
            
            const pythonBinary = '/home/ahmedjr/grad-proj/tools/cymatvenv/bin/python3'

            pythonProcess = spawn(pythonBinary, [scriptPath, ...args], {
                signal: controller.signal
            });

            let fullOutput = '';
            
            // Capture all output exactly as printed
            pythonProcess.stdout.on('data', (data) => {
                const text = data.toString();
                process.stdout.write(text); // Mirror to console
                fullOutput += text;
            });

            pythonProcess.stderr.on('data', (data) => {
                const text = data.toString();
                process.stderr.write(text); // Mirror errors to console
                fullOutput += text;
            });

            const exitCode = await new Promise((resolve, reject) => {
                pythonProcess.on('close', (code) => {
                    clearTimeout(timeoutId);
                    resolve(code);
                });
                pythonProcess.on('error', reject);
            });

            if (exitCode !== 0) {
                throw new Error(`Process exited with code ${exitCode}`);
            }

            return fullOutput;

        } catch (error) {
            if (timeoutId) clearTimeout(timeoutId);
            if (pythonProcess) pythonProcess.kill();
            
            console.error('Script execution error:', error);
            throw error;
        }
    }

    async executeScript(scriptName, args = []) {
        try {
            const scriptPath = await this.#getScriptPath(scriptName);
            return await this.#runPythonScript(scriptPath, args);
        } catch (err) {
            if (err.name === "AbortError") {
                throw new Error(`Script timed out after ${this.timeout}ms`)
            }
            throw err
    }
}

}












// Example usage

// Simulate 10 concurrent users
// const promises = [];
// for (let i = 0; i < 10; i++) {
//     promises.push(
//         pythonService.executeScript('dns', [`user${i}.example.com`])
//             .then(() => console.log(`Finished ${i}`))
//     );
// }

// await Promise.all(promises);
// console.log('All requests completed in parallel');
