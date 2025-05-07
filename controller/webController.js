
import { PythonService } from '../services/PythonService.js'

// Input Method: The script expects a single command-line argument: a URL. ex.(python script.py http://example.com)
const SSRFScanController = async (req, res) => {
    try {
        const domain = req.body.target || req.query.target
        console.log(req.body)
        console.log(req.query)
        
        console.log(`Domain: ${domain}`)
        
        if (!domain) {
            return res.status(400).send('Domain parameter is required')
        }

        const pythonService = new PythonService()
        const rawOutput = await pythonService.executeScript('SSRF Vulnerability Testing', [domain])
        
        res.setHeader('Content-Type', 'text/plain')
        return res.send(rawOutput)
    } catch (error) {
        console.error('DNS scan failed:', error)
        res.setHeader('Content-Type', 'text/plain')
        return res.status(500).send(`Error: ${error.message}`)
    }
}
export {
    SSRFScanController
}








































































































// const ipscanController = async (req, res) => {
//     try {
//         const { ip } = req.query || req.body?.ip || '192.165.1.1/24'
//         const name = req.params.name || 'Service Detection'
//         console.log(`IP: ${ip}, Name: ${name}`)
//         const range = '20-80'
        
//         if(!name || !ip) {
//             return res.status(400).send('Missing required parameters: name or ip');
//         }

//         const pythonService = new PythonService()
        
//         const rawOutput = await pythonService.executeScript(name , [ip , range])
        
//         // Return the complete raw output exactly as from terminal
//         res.setHeader('Content-Type', 'text/plain')
//         return res.send(rawOutput)

//     } catch (error) {
//         console.error('Scan failed:', error)
        
//         // Return error output in same format
//         res.setHeader('Content-Type', 'text/plain')
//         return res.status(500).send(`Error: ${error.message}`)
//     }
// };
