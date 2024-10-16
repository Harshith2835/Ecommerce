import mongoose from 'mongoose';

const dbURL = 'mongodb://127.0.0.1:27017/ecomm';

const connectdb = async () => {
    try {
        await mongoose.connect(dbURL);
        console.log('Connected to MongoDB successfully!');
    } catch (err) {
        console.error('Error connecting to MongoDB:', err.message);
    }
};

export default connectdb;
