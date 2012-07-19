bcrypt = require 'bcrypt'
express = require 'express'
redis = require('redis').createClient()

# Calls the callback with the encrypted password
encryptPassword = (password, callback) ->
    bcrypt.genSalt 10, (err, salt) ->
        bcrypt.hash password, salt, (err, hash) ->
            callback hash

# Calls the callback with true if the password matches the hash and false otherwise
validatePassword = (password, hash, callback) ->
    bcrypt.compare password, hash, (err, res) ->
        callback res

app = express.createServer()
app.set 'views', __dirname + '/templates'

app.use express.cookieParser()
app.use express.bodyParser()
app.use express.session
    secret: process.env.SESSION_SECRET || 'secret'
app.use express.static __dirname + '/static'

showError = (status, res) ->
    res.render status + '.jade', { status: status }

app.get '/', (req, res) ->
    if req.session.authenticated
        res.redirect '/inside'
    else
        res.render 'index.jade'

app.get '/inside', (req, res) ->
    if req.session.authenticated
        res.render 'inside.jade'
    else
        showError 401, res

app.post '/logout', (req, res) ->
    if req.session.authenticated
        req.session.destroy()
        res.redirect '/'
    else
        showError 401, res

app.get '/login', (req, res) ->
    if req.session.authenticated
        showError 401, res
    else
        res.render 'login.jade',
            form: {}
            validationFailed: false

app.post '/login', (req, res) ->
    if req.session.authenticated
        showError 401, res
    else
        # Called if there is a problem with the input
        validationError = (error) ->
            res.render 'login.jade',
                form: req.body,
                validationFailed: error

        if not req.body.name?
            validationError 'name'
            return
        else if not req.body.password?
            validationError 'password'
            return

        # Look up name
        redis.hgetall req.body.name, (err, user) ->
            if not user
                validationError 'name'
                return

            validatePassword req.body.password, user.password, (matches) ->
                if not matches
                    validationError 'password'
                    return

                req.session.authenticated = req.body.name
                res.redirect '/inside'

app.get '/signup', (req, res) ->
    if req.session.authenticated
        showError 401, res
    else
        res.render 'signup.jade',
            form: {}
            validationFailed: false

app.post '/signup', (req, res) ->
    if req.session.authenticated
        showError 401, res
    else
        # Called if there is a problem with the input
        validationError = (error) ->
            res.render 'signup.jade',
                form: req.body,
                validationFailed: true,
                validationError: error

        # Did we get some input?
        if not (req.body.name? and req.body.quest? and req.body.password?)
            validationError "I'm not letting you in until you answer <em>all</em>
                of my questions."
            return

        # Does this user already exist?
        redis.hgetall req.body.name, (err, exists) ->
            if exists?
                    validationError "We already have a #{req.body.name} in our club.
                        We can't have two of you running around."
                    return
            else
                encryptPassword req.body.password, (hash) ->
                    # Save user
                    redis.hmset req.body.name,
                        quest: req.body.quest,
                        password: hash
                    , () ->
                        req.session.authenticated = req.body.name
                        res.redirect '/inside'

app.get '*', (req, res) ->
    showError 404, res
app.post '*', (req, res) ->
    showError 404, res

app.listen process.env.PORT || 3776
