require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new(:test) do |t|
  t.test_files = FileList['test/**/*_test.rb', 'test/**/test_*.rb']
end

task default: :test
