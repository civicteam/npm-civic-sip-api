module.exports = function(grunt) {

  require('load-grunt-tasks')(grunt);

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    clean: {
      all: ['dist/']
    },
    copy: {
      dist: {
        files: [
          {
            expand: true,
            cwd: 'lib/',
            src: ['*.js', '**/*.js'],
            dest: 'dist/lib/'
          },
        ]
      }
    },
    babel: {
      options: {
        sourceMap: true,
        presets: ['babel-preset-es2015', 'babel-preset-es2017']
      },
      dist: {
        files: [
          {
            expand: true,
            cwd: 'lib/',
            src: ['*.js'],
            dest: 'dist/lib/'
          },
          {
            'dist/index.js': 'index.js',
            'dist/test/civic.js': 'test/civic.js'
          }
        ]
      }
    },
    watch: {
      lib: {
        files: [
          'index.js',
          'lib/*.js',
          'test/*.js'
        ],
        tasks: ['default']
      },
    }
  });

  grunt.loadNpmTasks('grunt-contrib-copy');
  grunt.loadNpmTasks('grunt-babel');
  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-watch');

  grunt.registerTask('default', ['clean', 'copy', 'babel']);
};