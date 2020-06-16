import React, { useState, FormEvent } from "react";
import { connect } from "react-redux";
import { Link } from "react-router-dom";
import Avatar from "./avatar";
import downArrow from "../../images/icons/down-arrow.svg";
import Dropdown from "./dropdown";
import Spinner from "./spinner";
import { selectBestAnswer } from "../../state/ducks/questions/actions";
import { deleteAnswer, postAnswer } from "../../state/ducks/answers/actions";
import { Answer } from "../../state/ducks/answers/types";
import { User } from "../../state/ducks/users/types";

interface AnswerProps {
  answer: Answer;
  users: Map<string, User>;
  currentUser: string;
  bestAnswer: number;
  questionUserId: string;
  selectBestAnswer: any;
  deleteAnswer: any;
  token: string;
}
function AnswerContent(props: AnswerProps) {
  const [showDropdown, setShowDropdown] = useState<boolean>(false);
  function handleReporting() {
    alert("Unfortunately, this action is not implemented yet!");
  }
  function handleUpdating() {
    alert("Unfortunately, this action is not implemented yet!");
  }
  function handleBestAnswer() {
    props.selectBestAnswer(props.answer.question_id, props.answer.id, props.token);
    setShowDropdown(false);
  }
  function handleDelete() {
    props.deleteAnswer(props.answer.id, props.token);
  }
  let user = props.users.get(props.answer.user_id);
  let job = "loading...",
    userName = "loading...";
  if (user) {
    userName = user.user_metadata
      ? user.user_metadata.firstname + " " + user.user_metadata.lastname
      : user.name;
    job = user.user_metadata ? user.user_metadata.job : "software engineer";
    // you've signed in using github :)
  }
  const currentUserAnswer = props.currentUser === props.answer.user_id;
  const currentUserQuestion = props.currentUser === props.questionUserId;
  const createdAt = new Date(props.answer.created_at);
  const isBestAnswer = props.bestAnswer === props.answer.id;
  return (
    <>
      <div className="card-header">
        <Avatar
          src={user?.picture || ""}
          info={{ name: userName, role: job }}
        />
        <div className="card-header-metadata">
          <p className="content">
            <small>
              {createdAt.toLocaleDateString()}
              <br />
              <span className="text-muted">
                {isBestAnswer ? "Accepted by user" : "Latest answer"}
              </span>
            </small>
          </p>
          <Dropdown
            useDropdown={[showDropdown, setShowDropdown]}
            btnContent={
              <img className="icon" src={downArrow} alt="down-arrow icon" />
            }
          >
            {!currentUserAnswer && (
              <button onClick={handleReporting}>Report this answer</button>
            )}
            {currentUserQuestion && (
              <button onClick={handleBestAnswer}>Select best answer</button>
            )}
            {currentUserAnswer && (
              <button onClick={handleUpdating}>Update answer</button>
            )}
            {currentUserAnswer && (
              <button onClick={handleDelete}>Delete answer</button>
            )}
          </Dropdown>
        </div>
      </div>
      <div className="card-body">
        <p className="card-text">{props.answer.content}</p>
      </div>
    </>
  );
}
interface Props {
  answer: Answer | undefined;
  users: Map<string, User>;
  token: string;
  currentUser: string;
  bestAnswer: number;
  answerExists: boolean;
  questionId: number;
  questionUserId: string;
  selectBestAnswer: any;
  deleteAnswer: any;
  postAnswer: any;
}
function AnswerSection(props: Props) {
  const [formActive, setFormActive] = useState<boolean>(false);
  const [textareaVal, setTextareaVal] = useState<string>("");
  function showForm() {
    setFormActive(true);
  }
  function hideForm() {
    if (textareaVal !== "") {
      const confirm = window.confirm("Discard what you have typed?");
      if (!confirm) {
        return;
      }
    }
    setTextareaVal("");
    setFormActive(false);
  }
  function handleSubmit(evt: FormEvent<HTMLFormElement>) {
    evt.preventDefault();
    props.postAnswer(props.questionId, textareaVal, props.token);
    setTextareaVal('');
    setFormActive(false)
  }
  return (
    <div className="card answer">
      {props.answerExists && !props.answer && (
        <div className="spinner-container" style={{ height: "60px" }}>
          <Spinner className="spinner-sm spinner-centered" />
        </div>
      )}
      {props.answer && (
        <AnswerContent
          answer={props.answer}
          users={props.users}
          currentUser={props.currentUser}
          bestAnswer={props.bestAnswer}
          questionUserId={props.questionUserId}
          selectBestAnswer={props.selectBestAnswer}
          token={props.token}
          deleteAnswer={props.deleteAnswer}
        />
      )}
      {props.answerExists && <hr />}
      <div className="answer-cta-section">
        <button className="btn btn-link" onClick={showForm}>
          Write an answer
        </button>
        {props.answerExists && (
          <Link to={`/${props.questionId}` || "/"} className="btn btn-link">
            View all answers
          </Link>
        )}
      </div>
      <hr />
      {formActive && (
        <form action="" className="answer-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <textarea
              name=""
              id=""
              rows={3}
              className="form-control"
              value={textareaVal}
              onChange={(evt) => {
                setTextareaVal(evt.currentTarget.value);
              }}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={textareaVal === ''}>
            Submit
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={hideForm}
          >
            Cancel
          </button>
        </form>
      )}
    </div>
  );
}

function mapStateToProps(state: any) {
  return {
    token: state.auth0.accessToken,
    currentUser: state.auth0.currentUser,
    users: state.users.entities,
  };
}
const mapDispatchToProps = {
  selectBestAnswer,
  deleteAnswer,
  postAnswer,
};
export default connect(mapStateToProps, mapDispatchToProps)(AnswerSection);
