const mongoose = require('mongoose');

const url = process.env.MONGODB_URL;
if (!url) {
    throw new Error("MONGODB_URL is not defined in the environment variables.");
}

const dbConnect = async () => {
    try {
        const connection = await mongoose.connect(url);
        console.log(`Connected to database: ${connection.connection.host}`);
    } catch (error) {
        console.error("Error connecting to the database:", error.message);
        process.exit(1);
    }
};

module.exports = dbConnect;
