
import multer from "multer"
import path from "path"

// Storage engine with forced .txt extension
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Make sure this folder exists
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, `${file.fieldname}-${uniqueSuffix}.txt`)
    }
});

const upload = multer({ 
    storage,
    fileFilter: function (req, file, cb) {
        // Optional: Accept only text-based mime types
        if (
            file.mimetype === 'text/plain' ||
            file.mimetype === 'application/json' || // if needed
            file.mimetype.startsWith('text/')       // covers .csv, .log, etc.
        ) {
            cb(null, true)
        } else {
            cb(new Error('Only text-based files are allowed'))
        }
    }
})

export default upload