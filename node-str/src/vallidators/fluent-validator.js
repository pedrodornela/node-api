'use strict';

let erros = [];

function ValidationContract() {
     erros = [];
}

ValidationContract.prototype.isRequired = (value, message) => {
    if (!value || value.length <= 0)
        erros.push({ message: message });
}

ValidationContract.prototype.hasMinLen = (value, min, message) => {
    if (!value || value.length < min)
        erros.push({ message: message });
}

ValidationContract.prototype.hasMaxlen = (value, max, message) => {
    if (!value || value.length > max)
        erros.push({ message: message });
}

ValidationContract.prototype.isFixedLen = (value, len, message) => {
    if (!value || value.length != len)
        erros.push({ message: message });
}

ValidationContract.prototype.isEmail = (value, message) => {
    var reg = new RegExp(/^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/);
    if (!reg.test(value))
        erros.push({ message: message });
}

ValidationContract.prototype.errors = () => {
    return erros;
}

ValidationContract.prototype.clear = () => {
    erros = [];
}

ValidationContract.prototype.isValid = () => {
    return erros.length == 0;    
}

module.exports = ValidationContract;
