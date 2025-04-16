
import express from "express"
import ipscanController from "../controller/ipscancontroller.js"

const router = express.Router()

router.get("/" , ipscanController)

export default router