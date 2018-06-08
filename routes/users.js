var express = require('express');
var router = express.Router();
var mongojs = require('mongojs');
var db = mongojs('passportapp',['users']);
var bcrypt = require('bcryptjs');
var passport = require('passport');
var LocalStrategy =require('passport-local').Strategy;

// Login page -GET
router.get('/login',function(req,res) {
	res.render('login');
});

// Register page _GET
router.get('/register',function(req,res) {
	res.render('register');
});

// Register -POST
router.post('/register',function(req,res) {
	//get form values
	var name       = req.body.name;
	var email      = req.body.email;
	var username   = req.body.username;
	var password   = req.body.password;
	var password2  = req.body.password2;

	//Validation
	req.checkBody('name','Name field is required').notEmpty();
	req.checkBody('email','Email field is required').notEmpty();
	req.checkBody('email','Please use valid email').isEmail();
	req.checkBody('password','Password field is required').notEmpty();
	req.checkBody('password2','Passwords so not match').equals(req.body.password);

	//check for errors

	var errors = req.validationErrors();
	if (errors) {
		console.log('Form has error...');
		res.render('register',{
			errors: errors,
			name: name,
			email:email,
			username:username,
			password: password,
			password2:password2		
		});
	}
	else{
		var newUser = {
			name:name,
			email:email,
			username:username,
			password:password
		}

		bcrypt.genSalt(10,function(err,salt){
			bcrypt.hash(newUser.password,salt,function(err,hash){
				newUser.password =hash;
				db.users.insert(newUser,function(err,doc){
					if (err) {
						res.send(err);
					}
					else{
						console.log('User Added ...');
						req.flash('success','You are register now And can log in ');
						res.location('/');
						res.redirect('/');
					}
				});
			});
		});

	}
});
 
passport.serializeUser(function(user, done) {
  done(null, user._id);
});

passport.deserializeUser(function(id, done) {
	db.users.findOne({_id:mongojs.ObjectId(id)},function(err,user){
		done(err,user);
	});
});


passport.use(new LocalStrategy(
		function(username,password,done){
			db.users.findOne({username:username},function(err,user){
				if(err){
					return done(err);
				}
				if(!user){
					return done(null,false,{message:'Incorrect username'});
				}

				bcrypt.compare(password,user.password,function(err,isMatch){
					if(err){
						return done(err);
					}
					if(isMatch){
						return done(null,user);
					}
					else{
						return done(null,false,{message:'Incorrect password'});						
					}
				});

 			});
		}
	));
 // Login --post
router.post('/login',
  passport.authenticate('local', { successRedirect: '/',
                                   failureRedirect: '/users/login',
                                   failureFlash: 'Invalid username or password' }),
  function(req,res){
  	console.log('Auth success');
  	res.redirect('/');
  });

router.get('/logout',function(req,res){
	req.logout();
	req.flash('success','You have logged out');
	res.redirect('/users/login');
});

module.exports = router; 