require File.expand_path(File.dirname(__FILE__) + '/../spec_helper.rb')

describe DataFixup::FixImportedQuestionMediaComments do
  it 'should fix broken yaml in questions and quizzes' do
    course
    placeholder = "SOMETEXT"
    bank = @course.assessment_question_banks.create!(:title => 'bank')
    data = {'question_name' => 'test question', 'question_type' => 'essay_question',
      'question_text' => "\n SOME OTHER TEXT \n #{placeholder} \n blahblahblah " }
    aq = bank.assessment_questions.build(:question_data => data)
    aq.migration_id = 'something'
    aq.save!

    quiz = @course.quizzes.create!(:title => "other quiz")
    qq = quiz.quiz_questions.build(:question_data => data)
    qq.migration_id = 'somethingelse'
    qq.save!
    quiz.generate_quiz_data
    quiz.published_at = Time.now
    quiz.workflow_state = 'available'
    quiz.save!

    broken_link = "<a class=\"media_comment\" href=\"stuff\">stuff</a>"

    #just in case someone tries to run this spec in the past
    updated_at = ActiveRecord::Base.connection.quote(DateTime.parse('2015-10-16'))
    # deliberately create broken yaml
    ActiveRecord::Base.connection.execute("UPDATE #{AssessmentQuestion.quoted_table_name} SET updated_at = #{updated_at},
      question_data = '#{aq['question_data'].to_yaml.gsub(placeholder, broken_link)}' WHERE id = #{aq.id}")
    ActiveRecord::Base.connection.execute("UPDATE #{Quizzes::QuizQuestion.quoted_table_name} SET updated_at = #{updated_at},
      question_data = '#{qq['question_data'].to_yaml.gsub(placeholder, broken_link)}' WHERE id = #{qq.id}")
    ActiveRecord::Base.connection.execute("UPDATE #{Quizzes::Quiz.quoted_table_name} SET updated_at = #{updated_at},
      quiz_data = '#{quiz['quiz_data'].to_yaml.gsub(placeholder, broken_link)}' WHERE id = #{quiz.id}")

    aq = AssessmentQuestion.where(:id => aq).first
    qq = Quizzes::QuizQuestion.where(:id => qq).first
    quiz = Quizzes::Quiz.where(:id => quiz).first

    expect((aq['question_data'] rescue nil)).to be_nil # Rails 4 raises errors when trying to deserialize
    expect((qq['question_data'] rescue nil)).to be_nil
    expect((quiz['quiz_data'] rescue nil)).to be_nil

    DataFixup::FixImportedQuestionMediaComments.run

    aq = AssessmentQuestion.where(:id => aq).first
    qq = Quizzes::QuizQuestion.where(:id => qq).first
    quiz = Quizzes::Quiz.where(:id => quiz).first

    expect(aq['question_data']['question_text']).to include(broken_link)
    expect(qq['question_data']['question_text']).to include(broken_link)
    expect(quiz['quiz_data'].first['question_text']).to include(broken_link)
  end
end