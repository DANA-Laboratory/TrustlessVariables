const Nothing = function(val) {
  this.value = val;
};
Nothing.of = function(val) {
  return new Nothing(val);
};
Nothing.prototype.map = function(f) {
  return this;
};
const Some = function(val) {
  this.value = val;
};
Some.of = function(val) {
  return new Some(val);
};
Some.prototype.map = function(fn) {
  return Some.of(fn(this.value));
}
const Either = {
  Some : Some,
  Nothing: Nothing
}
module.exports = Either;
