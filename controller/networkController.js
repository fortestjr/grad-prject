
import { PythonService } from '../services/PythonService.js'


const dnsScan = async (req, res) => {
    try {
        const { domain } = req.query;
        
        if (!domain) {
            return res.status(400).send('Domain parameter is required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('DNS Hostname Scanning', [domain])
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('DNS scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const firewallTest = async (req, res) => {
    try {
        const { target, protocol, ports } = req.query;
        
        if (!target || !protocol || !ports) {
            return res.status(400).send('Target, protocol, and ports parameters are required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Firewall and ACL Testing', [target, protocol, ports]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Firewall test failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const ipScan = async (req, res) => {
    try {
        const { cidr } = req.query;
        
        if (!cidr) {
            return res.status(400).send('CIDR parameter is required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('IP Scanning', [cidr]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('IP scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const portScan = async (req, res) => {
    try {
        const { target, range } = req.query;
        
        if (!target || !range) {
            return res.status(400).send('Target and range parameters are required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Port Scanning', [target, range]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Port scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const protocolScan = async (req, res) => {
    try {
        const { target } = req.query;
        
        if (!target) {
            return res.status(400).send('Target parameter is required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Protocol Analysis', [target]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Protocol scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const serviceDetect = async (req, res) => {
    try {
        const { target, versionDetection } = req.query;
        
        if (!target) {
            return res.status(400).send('Target parameter is required');
        }

        const args = [target];
        if (versionDetection === 'true') {
            args.push('--version-detection');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Service Detection', args);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Service detection failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const subnetScan = async (req, res) => {
    try {
        const { subnet, vlan } = req.query;
        
        if (!subnet || !vlan) {
            return res.status(400).send('Subnet and VLAN parameters are required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Subnet and VLAN Scanning', [subnet, vlan]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Subnet scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const latencyTest = async (req, res) => {
    try {
        const { target, count } = req.query;
        
        if (!target) {
            return res.status(400).send('Target parameter is required');
        }

        const args = [target];
        if (count) {
            args.push('-c', count);
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Latency Testing', args);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Latency test failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

export {
    dnsScan,
    firewallTest,
    ipScan,
    portScan,
    protocolScan,
    serviceDetect,
    subnetScan,
    latencyTest
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
