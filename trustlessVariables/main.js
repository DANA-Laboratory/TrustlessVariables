const fs = require('fs');
const error = require('./errors.js');
const either = require('./functional.js');
const Some = either.Some;
const Nothing = either.Nothing;
const addUpdate = (new_, array_, key_) => {
  if ((i = array_.findIndex((elem)=>(elem[key_] === new_[key_]))) >= 0)
    array_[i] = new_
  else
    array_.push(new_)
}

module.exports = {
  dataState : (inp) => {
      const users = inp ? inp.users : [];
      this.users = users;
      return this;
  },
  log : (in_) => console.log(in_),
  newUser : (name, family, id) => {return id ? Some.of({name: name, family: family, id:id}) : Nothing.of(error.no_id)},
  addUpdateUser : (user, ds) => addUpdate(user.value, ds.users, 'id'),
  write : (dataFilePath, ds) => {
    fs.writeFileSync(dataFilePath, JSON.stringify(ds));
  },
  load : (dataFilePath) => {
    return data = JSON.parse(fs.readFileSync(dataFilePath));
  },
}
