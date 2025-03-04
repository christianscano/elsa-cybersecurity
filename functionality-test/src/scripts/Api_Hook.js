Java.perform(function() {
    // Define the classes you want to hook
    var classesToHook = [
        {% for clazz in components %}
            "{{clazz}}"{% if not loop.last %},{% endif %}
        {% endfor %}
    ];

    // Function to hook all methods of a given class
    function hookAllMethods(className) {
        var clazz = Java.use(className);

        // Get the method names dynamically and hook each one
        var methodNames = Object.getOwnPropertyNames(clazz)
            .filter(function(name) {
                return typeof clazz[name] === 'function' && name !== '$init'; // Exclude the constructor
            });

        methodNames.forEach(function(methodName) {
            try {
                var method = clazz[methodName];
                if (method.overloads.length > 1) {
                        method.overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                console.log('Hooked ' + className + '.' + methodName + '(' + overload.argumentTypes.map(t => t.className).join(', ') + ')');
                                return overload.apply(this, arguments);
                            };
                        });
                    } else {
                        // Hook the method implementation
                        method.implementation = function() {
                            console.log('Hooked ' + className + '.' + methodName + '()');

                            return this[methodName].apply(this, arguments);
                        };
                    }
            } catch (e) {
                console.log('Failed to hook ' + className + '.' + methodName + ': ' + e.message);
            }
        });
    }

    // Hook methods for each class in the list
    classesToHook.forEach(function(className) {
        try {
            hookAllMethods(className);
        } catch (e) {
            console.log('Failed to hook methods for ' + className + ': ' + e.message);
        }
    });
});