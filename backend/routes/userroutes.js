import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/usermodel.js';
import { CreateUser, loginUser, logout, getAllUsers ,getUserProfile, updateCurrentUser, deleteuserbyid , getUserById, updateUserById } from '../controllers/userController.js';
import { authorizedAdmin,authenticate } from '../middleware/authmiddlware.js';

const router = express.Router();
router.route('/').post(CreateUser).get(authenticate,authorizedAdmin,getAllUsers);
router.post('/login',loginUser);
router.post('/logout',logout);
router.route('/profile').get(authenticate,getUserProfile).put(authenticate,updateCurrentUser);

//Admin routes
router.route('/:id')
.delete(authenticate,authorizedAdmin,deleteuserbyid)
.get(authenticate,authorizedAdmin,getUserById)
.put(authenticate,authorizedAdmin,updateUserById)

export default router;
