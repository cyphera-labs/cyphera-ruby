FROM ruby:3.3-slim
WORKDIR /app
COPY . .
CMD ["ruby", "test/test_all.rb"]
