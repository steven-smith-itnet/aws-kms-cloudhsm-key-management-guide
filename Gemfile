source "https://rubygems.org"

# Just the Docs — documentation theme
gem "just-the-docs", "0.10.1"

# Jekyll static site generator
gem "jekyll", "~> 4.3"

# Plugins
group :jekyll_plugins do
  gem "jekyll-seo-tag", "~> 2.8"
end

# Windows / JRuby helpers (harmless elsewhere)
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

# Faster file watching on Windows
gem "wdm", "~> 0.1.1", :platforms => [:mingw, :x64_mingw, :mswin]

# Ruby 3.4+ no longer ships these as default gems
gem "csv"
gem "base64"
gem "bigdecimal"
