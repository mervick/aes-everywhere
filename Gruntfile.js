/**
 * Gruntfile.js
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018
 * @license MIT
 */
/* jshint node: true */
'use strict';

module.exports = function (grunt) {
    require('load-grunt-tasks')(grunt);

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        browserify: function() {
            const dateFormat = require("dateformat");
            const path = 'javascript/';
            const src = [
                path + 'src/*.js'
            ];
            const dest = path + 'dist/aes256.js';
            const destMin = path + 'dist/aes256.min.js';
            const year = (new Date()).getFullYear();
            const banner =
                '/*!\n' +
                ' * aes256.js v<%= pkg.version %>\n' +
                ' * @author Andrey Izman <izmanw@gmail.com>\n' +
                ' * @copyright Andrey Izman (c) ' + year + '\n' +
                ' * @license MIT\n' +
                ' */';
            const paths = ['./node_modules', './javascript/src'];

            const babelify = {
                "presets" : ["es2015"],
            };

            return {
                'watch': {
                    src: src,
                    dest: dest,
                    options: {
                        debug: true,
                        watch: true,
                        keepAlive: true,
                        banner: banner,
                        browserifyOptions: {
                            debug: true,
                            paths: paths
                        },
                        postBundleCB: function (err, src, next) {
                            grunt.log.writeln('');
                            grunt.log.writeln('Time: ' + dateFormat(new Date(), "h:MM:ss.l")['yellow']);
                            next(err, src);
                        }
                    },
                    transform: [
                        ['babelify', babelify]
                    ]
                },

                'build': {
                    src: src,
                    dest: dest,
                    options: {
                        banner: banner,
                        browserifyOptions: {
                            debug: false,
                            paths: paths
                        }
                    },
                    transform: [
                        ['babelify', babelify]
                    ]
                },

                'minify': {
                    src: src,
                    dest: destMin,
                    options: {
                        banner: banner,
                        browserifyOptions: {
                            paths: paths
                        }
                    },
                    transform: [
                        ['babelify', babelify],
                        'uglifyify'
                    ]
                },
            };
        } ()
    });
};
