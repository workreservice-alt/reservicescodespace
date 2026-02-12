const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const User = require(path.join(__dirname, '..', '..', 'src', 'models', 'User'));

dotenv.config({ path: path.join(__dirname, '..', '..', '.env') });

const resetAdmin = async () => {
    try {
        console.log('Connecting to DB...');
        if (!process.env.MONGO_URI) {
            throw new Error('MONGO_URI is undefined');
        }
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected.');

        const email = 'admin@reservice.com';
        const newPassword = 'Admin@1234';

        const admin = await User.findOne({ email });
        if (!admin) {
            console.log('Admin user not found. Creating one...');
            await User.create({
                name: 'Super Admin',
                email,
                password: newPassword,
                role: 'ADMIN',
                phone: '0000000000',
                isTechnicianOnboarded: true
            });
            console.log('Admin created.');
        } else {
            console.log('Admin found. Updating password...');
            admin.password = newPassword;
            await admin.save();
            console.log('Password updated.');
        }

        console.log(`\n✅ Admin Credentials:\nEmail: ${email}\nPassword: ${newPassword}\n`);
        process.exit(0);
    } catch (error) {
        console.error('Error resetting admin:', error);
        process.exit(1);
    }
};

resetAdmin();
