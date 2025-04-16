import { spawn } from 'child_process'

import dbConnection from '../db/db.js'
import { rejects } from 'assert'
const db = await dbConnection()

export class PythonService {
    constructor(timeout){
        this.timeout = timeout || 30000
    }

// This function should return the path to the script

    async #getScriptPath(scriptName) {
        // Fetch the script from the database
        const script = await db.get('select path from SecurityTools where name = ?', [scriptName])
        // Check if the script exists

        if (!script) {
            throw new Error(`Script ${scriptName} not found in the database`)
        }
        return script.path
    }

    async #runPythonScript(scriptPath, args = []) {

        const controller = new AbortController()
        const timeoutId = setTimeout(() => { controller.abort() } , this.timeout)

        let pythonProcess = null
        
        try{
    
            pythonProcess = spawn('python3' , [scriptPath , ...args], {
                signal : controller.signal
            })
            let output = ''
            let errorOutput = ''

            pythonProcess.stdout.on ('data' , (data)=>{
                output += data.toString()
            
            })

            pythonProcess.stderr.on('data' , (data)=>{
                errorOutput += data.toString()
            })


            const exitCode = await new Promise((resolve, reject) => {
                pythonProcess.on('close', (code) => {
                    resolve(code);
                })
    
                pythonProcess.on('error', (err) => {
                    reject(err);
                })
            })

            clearTimeout(timeoutId)
            console.log("Python script output:", output)

            if (exitCode !== 0) {
                throw new Error(`Script failed (code ${exitCode}): ${errorOutput}`)
            }
        
            return output  // Return the output of the script

        } catch (err) {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError') {
                throw new Error(`Script timed out after ${this.timeout}ms`)
            }
            throw err 
        }finally {
            // Ensure cleanup if something throws unexpectedly
            if (pythonProcess) {
                pythonProcess.kill()
            }
        }
    }

    async executeScript(scriptName, args = []) {
        try {
            const scriptPath = await this.#getScriptPath(scriptName)
            return await this.#runPythonScript(scriptPath, args)
        } catch (err) {
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