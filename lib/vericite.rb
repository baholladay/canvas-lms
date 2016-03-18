#
# Copyright (C) 2011 - 2014 Instructure, Inc.
#
# This file is part of Canvas.
#
# Canvas is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3 of the License.
#
# Canvas is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.
#

require 'vericite/response'
require 'vericite_client'
require 'digest/sha1'
require 'date'

module VeriCite
  def self.state_from_similarity_score(similarity_score)
    return 'none' if similarity_score == 0
    return 'acceptable' if similarity_score < 25
    return 'warning' if similarity_score < 50
    return 'problem' if similarity_score < 75
    'failure'
  end

  class Client
    attr_accessor :endpoint, :account_id, :shared_secret, :host, :testing

    def initialize(account_id, shared_secret, host=nil, testing=false)
      @host = host || "api.vericite.com"
      @endpoint = "/api.asp"
      raise "Account ID required" unless account_id
      raise "Shared secret required" unless shared_secret
      @account_id = account_id
      @shared_secret = shared_secret
      @testing = testing
      @functions = {
        :create_user              => '1', # instructor or student
        :create_course            => '2', # instructor only
        :enroll_student           => '3', # student only
        :create_assignment        => '4', # instructor only
        :submit_paper             => '5', # student or teacher
        :generate_report          => '6',
        :show_paper               => '7',
        :delete_paper             => '8',
        :change_password          => '9',
        :list_papers              => '10',
        :check_user_paper         => '11',
        :view_admin_statistics    => '12',
        :view_grade_mark          => '13',
        :report_turnaround_times  => '14',
        :submission_scores        => '15',
        :login_user               => '17',
        :logout_user              => '18',
      }
    end

    def id(obj)
      if @testing
        "test_#{obj.asset_string}"
      elsif obj.respond_to?(:vericite_id)
        obj.vericite_asset_string
      else
        "#{account_id}_#{obj.asset_string}"
      end
    end

    def email(item)
      # emails @example.com are, guaranteed by RFCs, to be like /dev/null :)
      email = if item.is_a?(User)
                item.email
              elsif item.respond_to?(:vericite_id)
                "#{item.vericite_asset_string}@null.instructure.example.com"
              end
      email ||= "#{item.asset_string}@null.instructure.example.com"
    end

    VeriCiteUser = Struct.new(:asset_string,:first_name,:last_name,:name)

    def testSettings
      user = VeriCiteUser.new("admin_test","Admin","Test","Admin Test")
      res = createTeacher(user)
      res.success?
    end

    def createStudent(user)
      sendRequest(:create_user, 2, :user => user, :utp => '1')
    end

    def createTeacher(user)
      sendRequest(:create_user, 2, :user => user, :utp => '2')
    end

    def createCourse(course)
      sendRequest(:create_course, 2, :course => course, :user => course, :utp => '2')
    end

    def enrollStudent(course, student)
      sendRequest(:enroll_student, 2, :user => student, :course => course, :utp => '1', :tem => email(course))
    end

    def self.default_assignment_vericite_settings
      {
        :originality_report_visibility => 'immediate',
        :exclude_quoted => '1'
      }
    end

    def self.normalize_assignment_vericite_settings(settings)
      unless settings.nil?
        valid_keys = VeriCite::Client.default_assignment_vericite_settings.keys
        valid_keys << :created
        settings = settings.slice(*valid_keys)

        settings[:originality_report_visibility] = 'immediate' unless ['immediate', 'after_grading', 'after_due_date', 'never'].include?(settings[:originality_report_visibility])
        settings[:s_view_report] =  determine_student_visibility(settings[:originality_report_visibility])

        [:exclude_quoted].each do |key|
          bool = Canvas::Plugin.value_to_boolean(settings[key])
          settings[key] = bool ? '1' : '0'
        end
      end
      settings
    end

    def self.determine_student_visibility(originality_report_visibility)
      case originality_report_visibility
      when 'immediate', 'after_grading', 'after_due_date'
        "1"
      when 'never'
        "0"
      end
    end

    def createOrUpdateAssignment(assignment, settings)
      course = assignment.context
      today = course.time_zone.today
      settings = VeriCite::Client.normalize_assignment_vericite_settings(settings)

      response = sendRequest(:create_assignment, settings.delete(:created) ? '3' : '2', settings.merge!({
        :user => course,
        :course => course,
        :assignment => assignment,
        :utp => '2',
        :dtstart => "#{today.strftime} 00:00:00",
        :dtdue => "#{today.strftime} 00:00:00",
        :dtpost => "#{today.strftime} 00:00:00",
        :late_accept_flag => '1',
        :post => true
      }))

      response.success? ? { assignment_id: response.assignment_id } : response.error_hash
    end

    # if asset_string is passed in, only submit that attachment
    def submitPaper(submission, asset_string=nil)
      student = submission.user
      assignment = submission.assignment
      course = assignment.context
      opts = {
        :post => true,
        :utp => '1',
        :user => student,
        :course => course,
        :assignment => assignment,
        :tem => email(course),
        :role => submission.grants_right?(student, :grade) ? "Instructor" : "Learner"
      }
      responses = {}
      if submission.submission_type == 'online_upload'
        attachments = submission.attachments.select{ |a| a.vericiteable? && (asset_string.nil? || a.asset_string == asset_string) }
        attachments.each do |a|
          Rails.logger.info("VeriCite API attachment: #{a.content_type} size: #{a.size} displayName: #{a.display_name}");
          paper_id = a.id
          paper_title = File.basename(a.display_name, ".*")
          paper_ext = a.extension
          paper_type = a.content_type
          if paper_ext == nil
            paper_ext = ""
          end
          paper_size = 100 # File.size(
          responses[a.asset_string] = sendRequest(:submit_paper, '2', { :pid => paper_id, :ptl => paper_title, :pext => paper_ext, :ptype => paper_type, :psize => paper_size, :pdata => a.open(), :ptype => '2' }.merge!(opts))
        end
      elsif submission.submission_type == 'online_text_entry' && (asset_string.nil? || submission.asset_string == asset_string)
        paper_id = Digest::SHA1.hexdigest submission.plaintext_body
        paper_ext = "html"
        paper_title = "InlineSubmission"
        plain_text = "<html>#{submission.plaintext_body}</html>"
        paper_type = "text/html"
        paper_size = plain_text.bytesize
        
        responses[submission.asset_string] = sendRequest(:submit_paper, '2', {:pid => paper_id, :ptl => paper_title, :pext => paper_ext, :ptype => paper_type, :psize => paper_size, :pdata => plain_text, :ptype => "1" }.merge!(opts))
      else
        raise "Unsupported submission type for VeriCite integration: #{submission.submission_type}"
      end

      responses.keys.each do |asset_string|
        res = responses[asset_string]
        responses[asset_string] = res.success? ? {object_id: res.returned_object_id} : res.error_hash
      end

      responses
    end

    def generateReport(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data_hash[asset_string][:object_id] rescue nil
      res = nil
      res = sendRequest(:get_scores, 2, :oid => object_id, :utp => '2', :user => user, :course => course, :assignment => assignment) if object_id
      data = {}
      if res
        data[:similarity_score] = res.similarity_score
      end
      data
    end

    def submissionReportUrl(submission, current_user, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data_hash[asset_string][:object_id] rescue nil
      response = sendRequest(:generate_report, 1, :oid => object_id, :utp => '2', :current_user => current_user, :user => user, :course => course, :assignment => assignment)
      if response != nil
        response.report_url
      else
        nil
      end
    end

    def submissionStudentReportUrl(submission, current_user, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data_hash[asset_string][:object_id] rescue nil
      response = sendRequest(:generate_report, 1, :oid => object_id, :utp => '1', :current_user => current_user, :user => user, :course => course, :assignment => assignment, :tem => email(course))
      if response != nil
        response.report_url
      else
        nil
      end
    end

    def submissionPreviewUrl(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data_hash[asset_string][:object_id] rescue nil
      sendRequest(:show_paper, 1, :oid => object_id, :utp => '1', :user => user, :course => course, :assignment => assignment, :tem => email(course))
    end

    def submissionDownloadUrl(submission, asset_string)
      user = submission.user
      assignment = submission.assignment
      course = assignment.context
      object_id = submission.vericite_data_hash[asset_string][:object_id] rescue nil
      sendRequest(:show_paper, 1, :oid => object_id, :utp => '1', :user => user, :course => course, :assignment => assignment, :tem => email(course))
    end

    def listSubmissions(assignment)
      course = assignment.context
      sendRequest(:list_papers, 2, :assignment => assignment, :course => course, :user => course, :utp => '1', :tem => email(course))
    end


    def sendRequest(command, fcmd, args)
      Rails.logger.info("VeriCite API sendRequest: course: #{command}")
      
      vericite_config = VeriCiteClient::Configuration.new()
      vericite_config.host = @host
      vericite_config.base_path = '/api/v1' 
      # TODO remove
      vericite_config.debugging = true
      api_client = VeriCiteClient::ApiClient.new(vericite_config)
      vericite_client = VeriCiteClient::DefaultApi.new(api_client)
      
      user = args.delete :user
      course = args.delete :course
      assignment = args.delete :assignment
      # default response is "ok" since VeriCite doesn't implement all functions      
      response = VeriCite::Response.new()
      response.return_code = 1
      response.assignment_id = 1
      if assignment
        response.assignment_id = assignment.id
      end
      consumer = @account_id
      consumer_secret = @shared_secret
      if command == :create_assignment
        Rails.logger.info("VeriCite API sendRequest calling create_assignment : #{args['exclude_quoted']}")
               
        context_id = course.id
        
        assignment_id = assignment.id
        assignment_data = VeriCiteClient::AssignmentData.new()
        assignment_data.assignment_title = assignment.title != nil ? assignment.title : assignment_id
        assignment_data.assignment_instructions = assignment.description != nil ? assignment.description : ""
        assignment_data.assignment_exclude_quotes = args["exclude_quoted"] != nil && args["exclude_quoted"] == '1' ? true : false
        assignment_data.assignment_due_date = 0
        if assignment.due_at != nil
          # convert to epoch time in milli
          assignment_data.assignment_due_date = assignment.due_at.to_time.utc.to_i * 1000
        end
        assignment_data.assignment_grade = assignment.points_possible != nil ? assignment.points_possible : -1
        
        Rails.logger.info("VeriCite API sendRequest calling create_assignment: context_id: #{context_id}, assignment_id: #{assignment_id}, consumer: #{consumer}, consumer_secret: #{consumer_secret}, assignment_data: #{assignment_data.to_hash}, base_url: #{vericite_config.base_url}")
        vericite_client.assignments_context_id_assignment_id_post(context_id, assignment_id, consumer, consumer_secret, assignment_data)
      elsif command == :submit_paper
        Rails.logger.info("VeriCite API sendRequest calling submit_paper")
        
        context_id = course.id
        assignment_id = assignment.id
        user_id = user.id
        report_meta_data = VeriCiteClient::ReportMetaData.new()
        report_meta_data.user_first_name = user.first_name
        report_meta_data.user_last_name = user.last_name
        report_meta_data.user_email = email(user)
        report_meta_data.user_role = args[:role]
        if assignment
          report_meta_data.assignment_title = assignment.title != nil ? assignment.title : assignment_id
        end
        if course
          report_meta_data.context_title = course.name != nil ? course.name : context_id
        end
        external_content_data = VeriCiteClient::ExternalContentData.new()
        external_content_data.external_content_id = "#{consumer}/#{context_id}/#{assignment_id}/#{user_id}/#{args[:pid]}"
        external_content_data.file_name = args[:ptl]
        external_content_data.upload_content_type = args[:pext]
        external_content_data.upload_content_length = args[:psize]
        report_meta_data.external_content_data = external_content_data
        Rails.logger.info("VeriCite API sendRequest calling submit_paper context_id: #{context_id}, user_id: #{user_id}, assignment_id: #{assignment_id}, consumer: #{consumer}, consumer_secret: #{consumer_secret}, report_meta_data #{report_meta_data.to_hash}, base_url: #{vericite_config.base_url}")
        # @return [Array<ExternalContentUploadInfo>]
        externalContentUploadInfoArr = vericite_client.reports_submit_request_context_id_assignment_id_user_id_post(context_id, assignment_id, user_id, consumer, consumer_secret, report_meta_data)
        externalContentUploadInfoArr.each do |externalContentUploadInfo|
          #API will return an upload URL to store the submission
          Rails.logger.info("VeriCite API sendRequest calling submit_paper presigned: #{externalContentUploadInfo.url_post}")
          res = api_client.uploadfile(externalContentUploadInfo.url_post, args[:pdata])
          Rails.logger.info("VeriCite API response: #{res.body}")
        end
        response.returned_object_id = external_content_data.external_content_id
      elsif command == :get_scores
        Rails.logger.info("VeriCite API sendRequest calling get_scores")
        
        context_id = course.id
        assignment_id = assignment.id
        user_id = user.id
        
        # @return [Array<ReportScoreReponse>]
        Rails.logger.info("VeriCite API context_id: #{context_id}, assignment_id: #{assignment_id}, user_id: #{user_id}, xid: #{args[:oid]}")
        reportScoreReponseArr = vericite_client.reports_scores_context_id_get(context_id, consumer, consumer_secret, {:'assignment_id' => assignment_id, :'user_id' => user_id, :'external_content_id' => args[:oid]})
        reportScoreReponseArr.each do |reportScoreReponse|
          # should only be 1 answer
         Rails.logger.info("VeriCite API reportScoreReponseArr user: #{reportScoreReponse.user}, assignment: #{reportScoreReponse.assignment}, external_content_id: #{reportScoreReponse.external_content_id}, score: #{reportScoreReponse.score}")
          if reportScoreReponse.external_content_id ==  args[:oid] && reportScoreReponse.score.is_a?(Integer) && reportScoreReponse.score >= 0 
            Rails.logger.info("VeriCite API setting response score")   
            response.similarity_score = Float(reportScoreReponse.score)
          end
        end
      elsif command == :generate_report
        Rails.logger.info("VeriCite API sendRequest calling generate_report")
        
        context_id = course.id
        assignment_id_filter = assignment.id
        user_id = user.id
        current_user = args.delete :current_user
        token_user = current_user.id
        token_user_role = 'Learner'
        if args[:utp] == '2'
          #instructor
          token_user_role = 'Instructor'
        end
        Rails.logger.info("VeriCite API 7 #{token_user_role}")
        # @return [Array<ReportURLLinkReponse>]
        begin
          reportURLLinkReponseArr = vericite_client.reports_urls_context_id_get(context_id, assignment_id_filter, consumer, consumer_secret, token_user, token_user_role, {:'user_id_filter' => user_id, :'external_content_id_filter' => args[:oid]})
          Rails.logger.info("VeriCite API 8")
        rescue => e
          Rails.logger.info("VeriCite API error detected")
          Rails.logger.info("VeriCite API #{e}")
          Rails.logger.info("VeriCite API #{e.backtrace}")
        end
        reportURLLinkReponseArr.each do |reportURLLinkReponse|
          #should only be 1 url
          Rails.logger.info("VeriCite API: url: #{reportURLLinkReponse.url}  eId: #{reportURLLinkReponse.external_content_id}")
          if reportURLLinkReponse.external_content_id ==  args[:oid]
            response.report_url = reportURLLinkReponse.url
          end
        end
      elsif command == :enroll_student
        # not implemented, return default "ok"
        Rails.logger.info("VeriCite API sendRequest calling enroll_student")
      elsif command == :create_user
        # not implemented, return default "ok"
        Rails.logger.info("VeriCite API sendRequest calling create_user")
      elsif command == :create_course
        # not implemented, return default "ok"
        Rails.logger.info("VeriCite API sendRequest calling create_course")
      elsif command == :show_paper
        # not implemented, return default "ok"
        Rails.logger.info("VeriCite API sendRequest calling show_paper")
      elsif command == :list_papers
        # not implemented, return default "ok"
        Rails.logger.info("VeriCite API sendRequest calling list_papers")
      end


      return nil if @testing

      
      if response.error?
        Rails.logger.error("VeriCite API error for account_id #{@account_id}: error #{ response.return_code }")
        Rails.logger.error(params.to_json)
        Rails.logger.error(http_response.body)
      end
      response

    end
  end
end
