const mongoose = require('mongoose')

// creating mongoose schema 
const UserSchema = new mongoose.Schema(
	{
		username: { type: String, required: true, unique: true },
		password: { type: String, required: true },
		// tokens: [Object]
		tokens: [Object]
	},
	{ collection: 'users' }
)

const model = mongoose.model('UserSchema', UserSchema)

module.exports = model