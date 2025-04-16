
import { spawn } from 'child_process'
import { PythonService } from '../services/PythonService.js';

const ipscanController = async (req, res) => { 
    try {
      const { ip } = req.query || req.body?.ip || "192.168.1.1"
      if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
      }

      const scriptName = "IP Scanning"

      const pythonProcess = new PythonService(300000)

      console.log("Request received")

      const result = await pythonProcess.executeScript(scriptName, [ip])
      // Assuming the script returns JSON data
      // const jsonData = JSON.parse(result);
      // Check if the script returned an error
      // if (jsonData.error) {
      //   return res.status(500).json({ error: jsonData.error })
      // }
      
      // Return the JSON data as the response
      return res.status(200).json({"Output": result})  

    }catch (error) {
        console.error("Error in ipscanController:", error)
        return res.status(500).json({ error: 'Internal server error' })
    }
}

export default ipscanController