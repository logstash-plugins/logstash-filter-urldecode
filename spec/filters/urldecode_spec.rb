# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/urldecode"

describe LogStash::Filters::Urldecode do
  describe "urldecode of correct urlencoded data" do
    # The logstash config goes here.
    # At this time, only filters are supported.
    config <<-CONFIG
      filter {
        urldecode {
        }
      }
    CONFIG

    sample({"message" => "http%3A%2F%2Flogstash.net%2Fdocs%2F1.3.2%2Ffilters%2Furldecode"}) do
      expect(subject.get("message")).to eq "http://logstash.net/docs/1.3.2/filters/urldecode"
      expect(subject.get("tags")).to be_nil
    end
  end

  describe "urldecode of incorrect urlencoded data" do
    config <<-CONFIG
      filter {
        urldecode {
        }
      }
    CONFIG

    sample({"message" => "http://logstash.net/docs/1.3.2/filters/urldecode"}) do
      expect(subject.get("message")).to eq "http://logstash.net/docs/1.3.2/filters/urldecode"
      expect(subject.get("tags")).to be_nil
    end
  end

   describe "urldecode with all_fields set to true" do
    # The logstash config goes here.
    # At this time, only filters are supported.
    config <<-CONFIG
      filter {
        urldecode {
          all_fields => true
        }
      }
    CONFIG

    sample({"message" => "http%3A%2F%2Flogstash.net%2Fdocs%2F1.3.2%2Ffilters%2Furldecode", "nonencoded" => "http://logstash.net/docs/1.3.2/filters/urldecode"}) do
      expect(subject.get("message")).to eq "http://logstash.net/docs/1.3.2/filters/urldecode"
      expect(subject.get("nonencoded")).to eq "http://logstash.net/docs/1.3.2/filters/urldecode"
      expect(subject.get("tags")).to be_nil
    end
  end

   describe "urldecode should replace invalid UTF-8" do
     config <<-CONFIG
      filter {
        urldecode {}
      }
     CONFIG
     sample({"message" => "/a/sa/search?rgu=0;+%C3%BB%D3%D0%D5%D2%B5%BD=;+%B7%A2%CB%CD="}) do
       expect(subject.get("message")).to eq "/a/sa/search?rgu=0;+û\\xD3\\xD0\\xD5ҵ\\xBD=;+\\xB7\\xA2\\xCB\\xCD="
       expect(subject.get("tags")).to be_nil
     end
   end

   describe "urldecode should handle non RFC 3986 compliant strings with encoding in params portion" do
     config <<-CONFIG
      filter {
        urldecode {
          field => "url"
        }
      }
     CONFIG
     sample({"url" => "/fr/search-results?queryText=Organigramme%20de%20la%20Commission%20europ%C3%A9enne%201998&additionalTextParam=organigramme%20de%20la%20commission%20européenne%201998"}) do
       expect(subject.get("url")).to eq "/fr/search-results?queryText=Organigramme de la Commission européenne 1998&additionalTextParam=organigramme de la commission européenne 1998"
       expect(subject.get("tags")).to be_nil
     end
   end

   describe "urldecode should handle non RFC 3986 compliant strings with encoding in url portion" do
     config <<-CONFIG
      filter {
        urldecode {
          field => "url"
        }
      }
     CONFIG
     sample({"url" => "http%3A%2F%2Fl%C3%B8gstash.net%2Fd%C3%B8cs%2F1.3.2%2Ffilters%2Furldecøde?name=frødø%20båggins"}) do
       expect(subject.get("url")).to eq "http://løgstash.net/døcs/1.3.2/filters/urldecøde?name=frødø båggins"
       expect(subject.get("tags")).to be_nil
     end
   end

   describe "urldecode should handle hashes" do
     config <<-CONFIG
      filter {
        urldecode {}
      }
     CONFIG
     sample({"message" => {"url" => "http%3A%2F%2Flogstash.net%2Fdocs%2F1.3.2%2Ffilters%2Furldecode"}}) do
       expect(subject.get("[message][url]")).to eq "http://logstash.net/docs/1.3.2/filters/urldecode"
       expect(subject.get("tags")).to be_nil
     end
   end

   describe "urldecode should handle arrays" do
     config <<-CONFIG
      filter {
        urldecode {}
      }
     CONFIG
     sample({"message" => ["http%3A%2F%2Flogstash.net%2Fdocs%2F1.3.2%2Ffilters%2Furldecode"]}) do
       expect(subject.get("[message][0]")).to eq "http://logstash.net/docs/1.3.2/filters/urldecode"
       expect(subject.get("tags")).to be_nil
     end
   end
end
