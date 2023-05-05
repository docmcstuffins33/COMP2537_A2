require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();
const Joi = require("joi");

const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');


app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.set('view engine', 'ejs');

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/');
    }
}

function isAdmin(req) {
    if (req.session.user_type == "admin") {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req,res) => {
    if(!req.session.authenticated) {
        res.render("home_no_session");
    } else {
        res.render("home_session", {user: req.session.username});
    }
});

app.get('/signup', (req, res) => {
    res.render("signup", {anotherAccount: req.query.anotherAccount, nameMissing: req.query.nameMissing, 
        emailMissing: req.query.emailMissing, passwordMissing: req.query.passwordMissing})
});

app.post('/submituser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(20).required(),
			password: Joi.string().max(20).required()
		});

	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       var linkBack = "/signup?";
       if(username == ''){
        linkBack += "nameMissing=true&"
       }
       if(email == ''){
        linkBack += "emailMissing=true&"
       }
       if(password == ''){
        linkBack += "passwordMissing=true&"
       }
	   res.redirect(linkBack);
	   return;
   }
    const result = await userCollection.find({email: email}).project({email: 1, username: 1, password: 1, _id: 1}).toArray();
    if (result.length == 1) {
		res.redirect("/signup?anotherAccount=true");
		return;
	}

    var hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: 'user'});
	console.log("Inserted user");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.user_type = 'user';
	req.session.email = email;
	req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render("login", {noAccount: req.query.noAccount, wrongPassword: req.query.wrongPassword,
    emailMissing: req.query.emailMissing, passwordMissing: req.query.passwordMissing});
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   var linkBack = "/login?";
       if(email == ''){
        linkBack += "emailMissing=true&"
       }
       if(password == ''){
        linkBack += "passwordMissing=true&"
       }
	   res.redirect(linkBack);
	   return;
	}

    const result = await userCollection.find({email: email}).project({email: 1, username: 1, password: 1, user_type: 1, _id: 1}).toArray();
    console.log(result);
	if (result.length != 1) {
		res.redirect("/login?noAccount=true");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		res.redirect("/login?wrongPassword=true");
		return;
	}
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.get('/members', sessionValidation, (req,res) => {
    res.render("members", {username: req.session.username});
});

app.get("/admin", sessionValidation, adminAuthorization, async (req,res)=> {
    const result = await userCollection.find().project({username: 1, email: 1, user_type: 1, _id: 1}).toArray();

    res.render("admin", {users: result});
});

app.post('/promote', async(req,res) => {
    var email = req.query.email;
    await userCollection.updateOne({email: email}, {$set: {user_type: 'admin'}});
    res.redirect('/admin');
});

app.post('/demote', async(req,res) => {
    var email = req.query.email;
    await userCollection.updateOne({email: email}, {$set: {user_type: 'user'}});
    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("errorMessage", {error: "Page Not Found"});
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 