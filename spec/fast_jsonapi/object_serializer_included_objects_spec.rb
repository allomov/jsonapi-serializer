require 'spec_helper'

RSpec.describe FastJsonapi::ObjectSerializer do
  describe 'with active record' do
    ActiveRecord::Schema.define do
      self.verbose = false
      create_table :posts, force: true do |t|
        t.string :title
        t.text :body
        t.references :author
        t.timestamps null: false
      end
      create_table :comments, force: true do |t|
        t.string :body
        t.references :author
        t.timestamps null: false
      end
      create_table :users, force: true do |t|
        t.string :name
        t.timestamps null: false
      end
      create_table :post_status, force: true do |t|
        t.string :visitors_count
        t.references :post
        t.timestamps null: false
      end
    end

    module ActiveRecordModels
      class Post < ActiveRecord::Base
        has_many :comments, class_name: 'ActiveRecordModels::Comment'
        belongs_to :author, class_name: 'ActiveRecordModels::User'
        has_one :post_stats
      end

      class Comments < ActiveRecord::Base
        has_many :comments, class_name: 'ActiveRecordModels::Comment'
        belongs_to :author, class_name: 'ActiveRecordModels::User'
      end

      class User < ActiveRecord::Base
        has_many :posts
        has_many :comments
      end

      class PostStats < ActiveRecord::Base
        belongs_to :post
      end

      class PostSerializer
        include FastJsonapi::ObjectSerializer
        set_type :post
        set_id :id
        attributes :title, :body
        belongs_to :author
        has_many :comments
        has_one :post_stats
      end

      class CommentSerializer
        include FastJsonapi::ObjectSerializer
        set_type :comment
        set_id :id
        attributes :body
        belongs_to :author, record_type: :user
      end

      class UserSerializer
        include FastJsonapi::ObjectSerializer
        set_type :user
        set_id :id
        attributes :name
      end

      class PostStatsSerializer
        include FastJsonapi::ObjectSerializer
        set_type :post_stats
        set_id :id
        attributes :visitors_count
      end
    end

    describe "with included objects" do
      let!(:post_author) { ActiveRecordModels::User.create!(name: FFaker::Name.name) }
      let!(:comment_author_1) { ActiveRecordModels::User.create!(name: FFaker::Name.name) }
      let!(:comment_author_2) { ActiveRecordModels::User.create!(name: FFaker::Name.name) }
      let!(:user_without_comments) { ActiveRecordModels::User.create!(name: FFaker::Name.name) }
      let!(:post) { ActiveRecordModels::Post.create!(title: 'New Post', body: 'Body', author: post_author) }
      let!(:comment_1) { ActiveRecordModels::Comments.create!(body: 'Comment 1', author: comment_author_1) }
      let!(:comment_2) { ActiveRecordModels::Comments.create!(body: 'Comment 2', author: comment_author_2) }
      let!(:post_stats) { ActiveRecordModels::PostStats.create!(visitors_count: 100, post: post) }

      describe "get" do
      end

      it 'returns included objects' do
        options = { include: [:author, :'comments.author', :post_stats] }
        result = ActiveRecordModels::PostSerializer.new(post, options).serializable_hash
        expect(result[:included].size).to eq(3)
        expect(result[:included][0][:type]).to eq(:user)
        expect(result[:included][0][:id]).to eq(user.id.to_s)
        expect(result[:included][1][:type]).to eq(:comment)
        expect(result[:included][1][:id]).to eq(comment.id.to_s)
        expect(result[:included][2][:type]).to eq(:post_stats)
        expect(result[:included][2][:id]).to eq(post_stats.id.to_s)
      end

      it 'returns included objects with custom serializer' do
        options = { include: [:author, :'comments.author', :post_stats] }
        result = ActiveRecordModels::PostSerializer.new(post, options).serializable_hash
        expect(result[:included].size).to eq(3)
        expect(result[:included][0][:type]).to eq(:user)
        expect(result[:included][0][:id]).to eq(user.id.to_s)
        expect(result[:included][1][:type]).to eq(:comment)
        expect(result[:included][1][:id]).to eq(comment.id.to_s)
        expect(result[:included][2][:type]).to eq(:post_stats)
        expect(result[:included][2][:id]).to eq(post_stats.id.to_s)
      end

    end
  end
end
