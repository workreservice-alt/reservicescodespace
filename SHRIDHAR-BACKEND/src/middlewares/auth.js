const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/User');
const AppError = require('../utils/AppError');

exports.protect = async (req, res, next) => {
    try {
        let token;

        if (
            req.headers.authorization &&
            req.headers.authorization.startsWith('Bearer')
        ) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies.jwt) {
            token = req.cookies.jwt;
        }

        if (!token) {
            return next(new AppError('You are not logged in! Please log in to get access.', 401));
        }

        // 2) Verification token
        const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

        // 3) Check if user still exists
        const currentUser = await User.findById(decoded.id);
        if (!currentUser) {
            return next(
                new AppError(
                    'The user belonging to this token does no longer exist.',
                    401
                )
            );
        }

        // 4) Check if user is active (Not blocked by Admin)
        if (currentUser.isActive === false) {
            return next(new AppError('Your account has been deactivated. Please contact support.', 403));
        }

        // GRANT ACCESS TO PROTECTED ROUTE
        req.user = currentUser;
        res.locals.user = currentUser;
        next();
    } catch (err) {
        return next(new AppError('Invalid token or session expired', 401));
    }
};

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        // roles ['admin', 'worker']. role='user'
        if (!roles.includes(req.user.role)) {
            return next(
                new AppError('You do not have permission to perform this action', 403)
            );
        }
        next();
    };
};
