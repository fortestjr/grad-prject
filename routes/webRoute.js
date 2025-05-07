
import express from "express"

import {
    SSRFScanController
} from "../controller/webController.js"

const router = express.Router();

// SSRF Scanning
router.post("/ssrf", SSRFScanController)


export default router