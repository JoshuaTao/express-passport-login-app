const express =require('express');
const router =express.Router();
const bcrypt =require('bcryptjs')
const passport = require('passport');
const { forwardAuthenticated } = require('../config/auth');

const User = require('../user.model');

router.get('/register',forwardAuthenticated,(req,res)=>res.render('register'));

router.get('/login',forwardAuthenticated,(req,res)=>res.render('login'));

router.post('/register',(req,res)=>{
    const{name,email,password,password2} = req.body;
    //检查是否有输入错误
    let errors =[];
    if(!name||!email||!password||!password2){
        errors.push({msg:'Please enter all fields!'})
    }
    if(password.length<8){
        errors.push({msg:'Password is less than 8 characters!'})
    }
    if(password!=password2){
        errors.push({msg:'Passwords do not match!'})
    }

    if(errors.length>0){
        res.render('register',{
            errors,
            name,
            email,
            password,
            password2
        });
    }else{
       User.findOne({email})
       .then(user=>{
             //检查email是否已被使用
           if(user){
               errors.push({msg:'Email is already registered!'})
               res.render('register',{
                errors,
                name,
                email,
                password,
                password2
               })
           }else{
               const newUser= new User({
                name,
                email,
                password,
               })
               //密码加密
               bcrypt.genSalt(10, (err, salt)=> {
                bcrypt.hash(password, salt, function(err, hash) {
                   if (err) throw err;
                   newUser.password = hash 
                   newUser.save()
                   .then(user=>{
                      req.flash(
                        'success_msg',
                        'You are now registered and can log in'
                      );
                       res.redirect('/users/login')
                   })
                   .catch(err=>console.log(err))
                 });
               });
            }
       })
    }
})

router.post('/login',
         passport.authenticate('local', {
             successRedirect: '/dashboard',
             failureRedirect: '/users/login',
             failureFlash: true
         }) )

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
});

module.exports=router;