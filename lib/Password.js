var prompt = require('prompt');

function getPass(){
    return new Promise((resolve, reject) => {
        // This json object is used to configure what data will be retrieved from command line.
        var prompt_attributes = [
            {
                name: 'password',
                hidden: true
            }
        ];
        prompt.start();
        prompt.get(prompt_attributes, function (err, result) {
            if (err) {
                reject(err);
            }else {
                resolve(result.password);
            }
        });
    });
   
}

module.exports = {getPass};