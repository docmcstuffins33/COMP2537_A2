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

app.get('/', (req,res) => {
    if(!req.session.authenticated) {
    var html = `<h1>Welcome to the Archive</h1>
        <form action='/signup' method='redirect'>
            <button>Sign up</button>
        </form>
        <form action='/login' method='redirect'>
            <button>Log in</button>
        </form>
        `
    } else {
        var html = `
        <h1>Welcome to the Archive, ` + req.session.username+`</h1>
        <form action='/members' method='redirect'>
            <button>Go to members area</button>
        </form>
        <form action='/logout' method='redirect'>
            <button>Log out</button>
        </form>
    `;
    }
    res.send(html);
});

app.get('/signup', (req, res) => {

    var html = `
    <h1>Sign Up</h1>
    <form action='/submituser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `
    if (req.query.anotherAccount){
        html += ` <p>There is already another account using that email!</p>`
    }
    if (req.query.nameMissing){
        html += ` <p>Username Missing</p>`
    }
    if (req.query.emailMissing){
        html += ` <p>Email Missing</p>`
    }
    if (req.query.passwordMissing){
        html += ` <p>Password Missing</p>`
    }
    res.send(html);
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

	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("Inserted user");
    req.session.authenticated = true;
    req.session.username = username;
	req.session.email = email;
	req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    var html = `
    <h1>Log In</h1>
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `
    if (req.query.noAccount){
        html += ` <p>No account for this email!</p>`
    }
    if (req.query.wrongPassword){
        html += ` <p>Incorrect password for this account</p>`
    }
    if (req.query.emailMissing){
        html += ` <p>Email Missing</p>`
    }
    if (req.query.passwordMissing){
        html += ` <p>Password Missing</p>`
    }
    res.send(html);
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

    const result = await userCollection.find({email: email}).project({email: 1, username: 1, password: 1, _id: 1}).toArray();
    console.log(result);
	if (result.length != 1) {
		res.redirect("/login?noAccount=true");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.username = result[0].username;
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

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    var html = `
    <h1>Hello, ` + req.session.username +`!</h1>`;
    var cat = Math.floor(Math.random() * 10);
    switch (cat) {
        case 0:
            html += `<img src='/5.jpg' style='width:250px;'>`
            break;
        case 1:
            html += `<img src='/6_dollar.jpg' style='width:250px;'>`
            break;
        case 2:
            html += `<img src='/8_13_AM.jpg' style='width:250px;'>`
            break;
        case 3:
            html += `<img src='/amazed.gif' style='width:250px;'>`
            break;
        case 4:
            html += `<img src='/BLEEEGHHH.png' style='width:250px;'>`
            break;
        case 5:
            html += `<img src='/cat_staring.gif' style='width:250px;'>`
            break;
        case 6:
            html += `<img src='/god.png' style='width:250px;'>`
            break;
        case 7:
            html += `<img src='/learn_more.png' style='width:250px;'>`
            break;
        case 8:
            html += `<img src='/most_wanted.png' style='width:250px;'>`
            break;
        case 9:
            html += `<img src='/standing.gif' style='width:250px;'>`
            break;
        default:
            htmp += '<h2>Something went wrong while generating a cat... </h2>'
            break;
    }
    res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send(`<h1>Page not found - 404</h1>
    <img src='/jincpope.gif' style='width:250px'>`);
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 