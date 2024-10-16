import User from '../models/usermodel.js';
import asyncHandler from '../middleware/asyncHandler.js'; // Added `.js` for the correct import path
import bcrypt from 'bcryptjs';
import generateToken from '../utils/createToken.js';

const CreateUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        if (!username || !email || !password) {
            throw new Error("Please enter all Fields");
        }

        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Generate salt and hash the password correctly
        const salt = await bcrypt.genSalt(12);
        const hashedPass = await bcrypt.hash(password, salt); // Pass both the password and salt

        user = new User({
            username,
            email,
            password: hashedPass, // Corrected field name: `password`
        });

        await user.save();

        // Generate the JWT token and send it in a cookie (assumed generateToken sets the cookie)
        generateToken(res, user._id);

        res.status(201).json({
            user: {
                id: user._id,
                username: user.username, // Fixed typo `usernmae`
                email: user.email,
                isAdmin: user.isAdmin,
            },
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Find user by email
    const existingUser = await User.findOne({ email });

    if (existingUser) {
        // Compare provided password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, existingUser.password);

        if (isPasswordValid) {
            // If password is correct, generate token and return user data
            generateToken(res, existingUser._id);
            res.status(200).json({
                user: {
                    id: existingUser._id,
                    username: existingUser.username,
                    email: existingUser.email,
                    isAdmin: existingUser.isAdmin,
                },
            });
            return;
        } else {
            // Password is incorrect
            res.status(401).json({ message: 'Invalid email or password' });
            return;
        }
    } else {
        // If user is not found, return error
        res.status(401).json({ message: 'Invalid email or password' });
        return;
    }
});



const logout=asyncHandler(async(req,res)=>{
        res.cookie('jwt',"",{
            httpOnly:true,
            expires:new Date(0)
        })
        res.status(200).json({message:"logged Out Successfully"});
    })

const getAllUsers=asyncHandler(async (req, res) => {
    // Find all users in the database, excluding the password field
    const users = await User.find({}).select('-password');
    
    res.status(200).json(users);
});

const getUserProfile=asyncHandler(async (req, res) => {
    // Find all users in the database, excluding the password field
    const user = await User.findById(req.user._id);
    if(user){
        res.json({
            _id:user._id,
            username:user.username,
            email:user.email
        })
    }
    else{
        throw new Error("user not found")
    }
});
const updateCurrentUser=asyncHandler(async (req, res) => {
    // Find all users in the database, excluding the password field
    const user = await User.findById(req.user._id);
    if(user){
        user.username=req.body.username || user.username
        user.email=req.body.email || user.email
        if(req.body.passowrd)
        {
            const salt = await bcrypt.genSalt(12);
            const hashedPass = await bcrypt.hash(req.body.password, salt); // Pass both the password and salt
            user.password=hashedPass
        }

        const updatedUser=await user.save();
        res.json({
            _id:updatedUser._id,
            username:updatedUser.username,
            email:updatedUser.email,
            isAdmin:updatedUser.isAdmin
        })
    }
    else{
        res.status(404);
        throw new Error("user not found")
    }
});
const deleteuserbyid = asyncHandler(async (req, res) => {
    try {
        const user = await User.findById(req.params.id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Check if the user to be deleted is an admin
        if (user.isAdmin) {
            return res.status(403).json({ message: 'Cannot remove an admin user' });
        }

        // Proceed with removing the user if not an admin
        await User.deleteOne({_id:user._id});
        res.status(200).json({ message: 'User removed successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

const getUserById = asyncHandler(async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (user) {
            res.status(200).json(user);
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});
const updateUserById = asyncHandler(async (req, res) => {
    const userId = req.params.id; // Get user ID from URL parameters

    // Find the user by ID
    const user = await User.findById(userId);

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    // Update user fields based on request body if provided
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    
    // Only admins can update the isAdmin field
    if (req.body.isAdmin !== undefined && req.user.isAdmin) {
        user.isAdmin = req.body.isAdmin;
    }

    // Save the updated user
    const updatedUser = await user.save();

    // Return updated user info (exclude password for security)
    res.status(200).json({
        user: {
            id: updatedUser._id,
            username: updatedUser.username,
            email: updatedUser.email,
            isAdmin: updatedUser.isAdmin,
        },
    });
});



export { CreateUser , loginUser, logout , getAllUsers, getUserProfile, updateCurrentUser , deleteuserbyid, getUserById, updateUserById};
